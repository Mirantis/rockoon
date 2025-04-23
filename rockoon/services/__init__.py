#    Copyright 2020 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import asyncio
import base64
from datetime import datetime, timezone
import json
import random

import kopf
import openstack
from openstack import exceptions
import pykube

from rockoon import ceph_api
from rockoon import constants
from rockoon import helm
from rockoon import layers
from rockoon import kube
from rockoon import maintenance
from rockoon import openstack_utils
from rockoon import secrets
from rockoon import settings
from rockoon import utils
from rockoon.services.base import (
    Service,
    OpenStackService,
    OpenStackServiceWithCeph,
    MaintenanceApiMixin,
)
from urllib.parse import urlsplit


LOG = utils.get_logger(__name__)
CONF = settings.CONF

# INFRA SERVICES


class Ingress(Service):
    service = "ingress"
    available_releases = ["ingress-openstack"]

    @property
    def health_groups(self):
        return ["ingress"]


class FederationMixin:

    @property
    def federation_redirect_uri(self):
        public_domain = self.mspec["public_domain_name"]
        keystone_base = f"https://keystone.{public_domain}"
        redirect_uri = f"{keystone_base}/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/mapped/websso/"
        return redirect_uri

    def _get_federation_default_provider_mapping(self):
        return [
            {
                "local": [
                    {"user": {"email": "{1}", "name": "{0}"}},
                    {"domain": {"name": "Default"}, "groups": "{2}"},
                ],
                "remote": [
                    {"type": "OIDC-iam_username"},
                    {"type": "OIDC-email"},
                    {"type": "OIDC-iam_roles"},
                ],
            }
        ]

    def _get_federation_provider_defaults(self, issuer):
        well_known = f"{issuer}/.well-known/openid-configuration"
        return {
            # Do not specify mapping here, since its list we will not able to merge correctly
            "enabled": True,
            "issuer": issuer,
            "metadata": {
                "client": {"client_id": "os"},
                "conf": {
                    "response_type": "id_token",
                    "scope": "openid email profile",
                    "ssl_validate_server": False,
                },
                "provider": {"value_from": {"from_url": {"url": well_known}}},
            },
            "oauth2": {"OAuth2TargetPass": "prefix=OIDC-"},
        }

    def _get_federation_keycloak_provider(self):
        keycloak_params = (
            self.mspec.get("features", {})
            .get("keystone", {})
            .get("keycloak", {})
        )
        issuer = f"{keycloak_params['url']}/auth/realms/iam"
        args = self._get_federation_provider_defaults(issuer)

        if keycloak_params["enabled"]:
            # Get IAM CA certificate
            oidc_ca_secret = (
                self.mspec["features"]
                .get("keystone", {})
                .get("keycloak", {})
                .get("oidc")
                .get("oidcCASecret")
            )
            if oidc_ca_secret:
                kube.wait_for_secret(
                    self.namespace,
                    oidc_ca_secret,
                )
                oidc_ca_bundle = base64.b64decode(
                    secrets.get_secret_data(
                        self.namespace,
                        oidc_ca_secret,
                    )["ca-cert.pem"]
                ).decode()
                args["oidc_ca"] = oidc_ca_bundle

        if "OIDCClientID" in keycloak_params:
            args["metadata"]["client"]["client_id"] = keycloak_params[
                "OIDCClientID"
            ]
        for global_opt, conf_opt in [
            ("OIDCSSLValidateServer", "ssl_validate_server"),
            ("OIDCScope", "scope"),
        ]:
            if global_opt in keycloak_params.get("oidc", {}):
                args["metadata"]["conf"][conf_opt] = keycloak_params["oidc"][
                    global_opt
                ]

        args["metadata"]["conf"][
            "oauth_verify_jwks_uri"
        ] = f"{keycloak_params['url']}/auth/realms/iam/protocol/openid-connect/certs"
        args["metadata"]["conf"]["verify_jwks_uri"] = args["metadata"]["conf"][
            "oauth_verify_jwks_uri"
        ]

        args["oauth2"][
            "OAuth2TokenVerify"
        ] = f"jwks_uri {keycloak_params['url']}/auth/realms/iam/protocol/openid-connect/certs jwks_uri.ssl_verify=false"
        args["description"] = "External Authentication Service"

        return args

    def get_federation_args(self):

        def _normalize_oidc_value(settings):
            for opt, value in settings.items():
                if isinstance(value, bool):
                    if value:
                        settings[opt] = "On"
                    else:
                        settings[opt] = "Off"

        mspec_federation = (
            self.mspec["features"].get("keystone", {}).get("federation", {})
        )

        # Supported auth types oauth20 (legacy) or oauth2
        federation_openid = {
            "enabled": mspec_federation.get("openid", {}).get(
                "enabled",
                self.mspec["features"]
                .get("keystone", {})
                .get("keycloak", {})
                .get("enabled", False),
            ),
            "oidc_auth_type": mspec_federation.get("openid", {}).get(
                "oidc_auth_type", "oauth2"
            ),
            "oidc": {
                "OIDCClaimPrefix": "OIDC-",
                "OIDCClaimDelimiter": ";",
                "OIDCOAuthSSLValidateServer": False,
                "OIDCSessionInactivityTimeout": "1800",
                "OIDCRedirectURI": self.federation_redirect_uri,
            },
        }

        providers = {}
        for provider_name, provider_opts in (
            mspec_federation.get("openid", {}).get("providers", {}).items()
        ):
            if provider_name == "keycloak":
                provider = self._get_federation_keycloak_provider()
            else:
                provider = self._get_federation_provider_defaults(
                    provider_opts["issuer"]
                )
            utils.merger.merge(provider, provider_opts)
            provider["mapping"] = provider_opts.get(
                "mapping", self._get_federation_default_provider_mapping()
            )
            providers[provider_name] = provider

        if len(providers.keys()) == 0:
            if (
                self.mspec["features"]
                .get("keystone", {})
                .get("keycloak", {})
                .get("enabled", False)
            ):
                providers["keycloak"] = (
                    self._get_federation_keycloak_provider()
                )
                providers["keycloak"][
                    "mapping"
                ] = self._get_federation_default_provider_mapping()
                federation_openid["oidc_auth_type"] = "oauth20"

        federation_openid["providers"] = providers

        # TODO(vsaienko): remove when keystone:keycloack is removed
        if federation_openid["oidc_auth_type"] == "oauth20":
            provider_opts = {}
            for opts in providers.values():
                if opts["enabled"]:
                    provider_opts = opts
                    break
            if provider_opts:
                oidc_provider_opts = {
                    "OIDCClientID": provider_opts["metadata"]["client"][
                        "client_id"
                    ],
                    "OIDCResponseType": provider_opts["metadata"]["conf"][
                        "response_type"
                    ],
                    "OIDCScope": provider_opts["metadata"]["conf"]["scope"],
                    "OIDCSSLValidateServer": provider_opts["metadata"]["conf"][
                        "ssl_validate_server"
                    ],
                    "OIDCOAuthSSLValidateServer": provider_opts["metadata"][
                        "conf"
                    ]["ssl_validate_server"],
                    "OIDCProviderMetadataURL": f"{provider_opts['issuer']}/.well-known/openid-configuration",
                    "OIDCOAuthVerifyJwksUri": provider_opts["metadata"][
                        "conf"
                    ]["oauth_verify_jwks_uri"],
                }
                utils.merger.merge(
                    federation_openid["oidc"], oidc_provider_opts
                )

        federation_openid["oidc"].update(
            self.mspec["features"]
            .get("keystone", {})
            .get("federation", {})
            .get("openid", {})
            .get("oidc", {})
        )
        oidc_ca_bundle = ""
        for provider_opts in federation_openid["providers"].values():
            if provider_opts["enabled"]:
                oidc_ca = provider_opts.get("oidc_ca")
                if oidc_ca:
                    oidc_ca_bundle += oidc_ca

        if oidc_ca_bundle:
            federation_openid["oidc_ca_bundle"] = oidc_ca_bundle

        if federation_openid["enabled"]:
            # set global parameters
            keycloak_salt = secrets.KeycloakSecret(self.namespace)
            keycloak_salt.ensure()
            federation_openid["oidc"][
                "OIDCCryptoPassphrase"
            ] = keycloak_salt.get().passphrase
            federation_openid["oidc"][
                "OIDCRedirectURI"
            ] = self.federation_redirect_uri
            if (
                federation_openid["oidc"].get("OIDCRedirectURLsAllowed")
                is None
            ):
                federation_openid["oidc"][
                    "OIDCRedirectURLsAllowed"
                ] = f"^https://horizon.{self.mspec['public_domain_name']}/auth/logout$"

        _normalize_oidc_value(federation_openid["oidc"])

        return {"federation": {"openid": federation_openid}}


class Coordination(Service, MaintenanceApiMixin):
    service = "coordination"
    available_releases = ["etcd"]

    @property
    def health_groups(self):
        return ["etcd"]

    async def remove_node_from_scheduling(self, node):
        pass

    async def prepare_node_for_reboot(self, node):
        pass

    async def prepare_node_after_reboot(self, node):
        pass

    async def add_node_to_scheduling(self, node):
        pass

    async def can_handle_nmr(self, node, locks):
        if await self.is_node_locked(node.name):
            LOG.error(f"The node {node.name} is hard locked by etcd.")
            return False
        return True

    async def process_ndr(self, node, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node.name} is hard locked by etcd."
            raise kopf.TemporaryError(msg)

    async def cleanup_persistent_data(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node_name} is hard locked by etcd."
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)
        server_sts = self.get_child_object("StatefulSet", "etcd-etcd")
        server_sts.release_persistent_volume_claims(node_name)

    async def is_node_locked(self, node_name):
        server_sts = self.get_child_object("StatefulSet", "etcd-etcd")
        return server_sts.is_node_locked(node_name)


class Redis(Service, MaintenanceApiMixin):

    service = "redis"
    available_releases = ["openstack-redis-operator"]

    @property
    def namespace(self):
        return settings.OSCTL_REDIS_NAMESPACE

    @property
    def health_groups(self):
        return []

    def template_args(self):
        redis_secret = secrets.RedisSecret(self.namespace)
        redis_secret.ensure()
        return {"redis_creds": redis_secret.get()}

    async def apply(self, event, **kwargs):
        # ensure child ref exists in the current status of osdpl object
        self.set_children_status("Applying")
        LOG.info(f"Applying config for {self.service}")
        data = self.render()

        # TODO(vsaienko): remove in 25.2 release
        helm_manager = helm.HelmManager(namespace=self.namespace)
        if await helm_manager.exist("os-redis-operator"):
            LOG.info(f"Purging os-redis-operator helm release")
            await helm_manager.delete("os-redis-operator")
        redis_failover = kube.find(
            kube.RedisFailover,
            "openstack-redis",
            settings.OSCTL_REDIS_NAMESPACE,
            silent=True,
        )
        if (
            redis_failover
            and redis_failover.exists()
            and redis_failover.obj["metadata"]
            .get("labels", {})
            .get("app.kubernetes.io/managed-by")
            != "Helm"
        ):
            redis_failover.delete()

        rfs_deployment = kube.find(
            kube.Deployment,
            "rfs-openstack-redis",
            settings.OSCTL_REDIS_NAMESPACE,
            silent=True,
        )
        operator_deployment = kube.find(
            kube.Deployment,
            "openstack-redis-operator",
            settings.OSCTL_REDIS_NAMESPACE,
            silent=True,
        )
        # PRODX-34488: to avoid races when image of sentinel is changed use cold start
        if rfs_deployment and rfs_deployment.exists():
            new_image = data["spec"]["releases"][0]["values"]["redisfailover"][
                "spec"
            ]["sentinel"]["image"]
            if not rfs_deployment.image_applied(new_image):
                LOG.info(f"Redis sentinel image is changed.")
                operator_deployment = kube.find(
                    kube.Deployment,
                    "openstack-redis-operator",
                    settings.OSCTL_REDIS_NAMESPACE,
                    silent=True,
                )
                rfr_statefulset = kube.find(
                    kube.StatefulSet,
                    "rfr-openstack-redis",
                    settings.OSCTL_REDIS_NAMESPACE,
                    silent=True,
                )
                for obj in [
                    operator_deployment,
                    rfr_statefulset,
                    rfs_deployment,
                ]:
                    if obj and obj.exists():
                        obj.reload()
                        obj.scale(0)
                        await obj.wait_for_replicas(0)
        await super().apply(event, **kwargs)

    async def remove_node_from_scheduling(self, node):
        pass

    async def prepare_node_for_reboot(self, node):
        pass

    async def prepare_node_after_reboot(self, node):
        pass

    async def add_node_to_scheduling(self, node):
        pass

    async def can_handle_nmr(self, node, locks):
        if await self.is_node_locked(node.name):
            LOG.error(f"The node {node.name} is hard locked by redis.")
            return False
        return True

    async def process_ndr(self, node, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node.name} is hard locked by redis."
            raise kopf.TemporaryError(msg)

    async def cleanup_persistent_data(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node_name} is hard locked by redis."
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

        rfr_sts = kube.find(
            kube.StatefulSet,
            "rfr-openstack-redis",
            settings.OSCTL_REDIS_NAMESPACE,
            silent=True,
        )
        if rfr_sts and rfr_sts.exists():
            rfr_sts.release_persistent_volume_claims(node_name)

    async def is_node_locked(self, node_name):
        rfr_sts = kube.find(
            kube.StatefulSet,
            "rfr-openstack-redis",
            settings.OSCTL_REDIS_NAMESPACE,
            silent=True,
        )
        if rfr_sts and rfr_sts.exists():
            return rfr_sts.is_node_locked(node_name)


class MariaDB(Service, MaintenanceApiMixin):
    service = "database"
    available_releases = ["openstack-mariadb"]

    @property
    def health_groups(self):
        return ["mariadb"]

    def template_args(self):
        admin_creds = self._get_admin_creds()
        galera_secret = secrets.GaleraSecret(self.namespace)
        galera_secret.ensure()
        return {
            "admin_creds": admin_creds,
            "galera_creds": galera_secret.get(),
            "network_policies": self.child_view.network_policies,
            "service_childs": self.child_view.childs,
        }

    async def remove_node_from_scheduling(self, node):
        pass

    async def prepare_node_for_reboot(self, node):
        pass

    async def prepare_node_after_reboot(self, node):
        pass

    async def add_node_to_scheduling(self, node):
        pass

    async def can_handle_nmr(self, node, locks):
        if await self.is_node_locked(node.name):
            LOG.error(f"The node {node.name} is hard locked by mariadb.")
            return False
        return True

    async def process_ndr(self, node, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node.name} is hard locked by mariadb."
            raise kopf.TemporaryError(msg)

    async def cleanup_persistent_data(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        if await self.is_node_locked(node_name):
            msg = f"The node {node_name} is hard locked by mariadb."
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)
        server_sts = self.get_child_object("StatefulSet", "mariadb-server")
        server_sts.release_persistent_volume_claims(node_name)

    async def is_node_locked(self, node_name):
        server_sts = self.get_child_object("StatefulSet", "mariadb-server")
        return server_sts.is_node_locked(node_name)


class Memcached(Service):
    service = "memcached"
    available_releases = ["openstack-memcached"]

    @property
    def health_groups(self):
        return ["memcached"]


class RabbitMQ(Service):
    service = "messaging"
    available_releases = ["openstack-rabbitmq"]

    @property
    def health_groups(self):
        return ["rabbitmq"]

    def template_args(self):
        credentials = {}
        notifications_creds = {}
        tls_external_certs = {}
        admin_creds = self._get_admin_creds()
        guest_creds = self._get_guest_creds()
        services = set(self.mspec["features"].get("services", [])) - set(
            ["tempest"]
        )
        for s in services:
            if s not in constants.OS_SERVICES_MAP:
                continue
            # NOTE(vsaienko): we need service passwords here.
            secret = Service.registry[s](
                self.mspec, self.logger, self.osdplst, self.child_view
            ).service_secret
            secret.wait()
            credentials[s] = secret.get_all()

        sl_secret = secrets.StackLightPasswordSecret(self.namespace)
        sl_secret.ensure()
        credentials["stacklight"] = sl_secret.get()

        if utils.get_in(self.mspec, ["features", "stacklight", "enabled"]):
            sls_data = {
                "username": credentials["stacklight"].username,
                "password": credentials["stacklight"].password,
                "hosts": json.dumps(
                    [
                        f"openstack-rabbitmq-rabbitmq-0.rabbitmq.{self.namespace}.svc.{self.mspec['internal_domain_name']}:5672"
                    ]
                ),
                "vhost": "/openstack",
            }
            secrets.StackLightSecret().save(
                {
                    k: base64.b64encode(v.encode()).decode()
                    for k, v in sls_data.items()
                }
            )

        cloudprober_enabled = "cloudprober" in services
        portprober_default = (
            self.openstack_version
            not in [
                "queens",
                "rocky",
                "stein",
                "train",
                "ussuri",
                "victoria",
                "wallaby",
                "xena",
                "yoga",
                "zed",
            ]
            and utils.get_in(self.mspec["features"], ["neutron", "backend"])
            not in ["tungstenfabric", "ml2/ovn"]
            and cloudprober_enabled
        )
        portprober_enabled = (
            self.mspec.get("features", {})
            .get("neutron", {})
            .get("extensions", {})
            .get("portprober", {})
            .get("enabled", portprober_default)
        )

        sl_config_data = {
            "conf.json": {
                "exporters": {
                    "cloudprober": {"enabled": cloudprober_enabled},
                    "portprober": {"enabled": portprober_enabled},
                }
            }
        }
        secrets.StackLightConfigSecret().save(sl_config_data)

        external_topics_enabled = (
            self.mspec.get("features", {})
            .get("messaging", {})
            .get("notifications", {})
            .get("external", {})
            .get("enabled", False)
        )

        if external_topics_enabled:
            external_topics = self.mspec["features"]["messaging"][
                "notifications"
            ]["external"].get("topics", [])
            for topic in external_topics:
                name = utils.get_topic_normalized_name(topic)
                topic_secret = secrets.ExternalTopicPasswordSecret(
                    self.namespace, topic, name
                )
                topic_secret.ensure()
                notifications_creds[topic] = topic_secret.get()

            # generate and store certificates for TLS connections
            # NOTE: server hostname checks are optional and generally has no
            # effect on certificate chain verification performed by the client.
            tls_external_certs_secret = secrets.SignedCertificatePackSecret(
                self.namespace,
                "rabbitmq-external",
                f"openstack-rabbitmq-rabbitmq-0.rabbitmq.{self.namespace}.svc.{self.mspec['internal_domain_name']}",
                f"*.{self.mspec['public_domain_name']}",
            )
            tls_external_certs_secret.ensure()
            tls_external_certs = tls_external_certs_secret.get()

        return {
            "services": services,
            "credentials": credentials,
            "admin_creds": admin_creds,
            "guest_creds": guest_creds,
            "notifications_creds": notifications_creds,
            "tls_external_certs": tls_external_certs,
            "network_policies": self.child_view.network_policies,
            "service_childs": self.child_view.childs,
        }


class Descheduler(Service):
    service = "descheduler"
    available_releases = ["openstack-descheduler"]

    def template_args(self):
        t_args = super().template_args()
        t_args["openstack_namespace"] = self.namespace
        return t_args

    @property
    def health_groups(self):
        return []


class Aodh(OpenStackService):
    service = "alarming"
    openstack_chart = "aodh"
    available_releases = ["openstack-aodh"]
    _protected_accounts = ["aodh"]


class Panko(OpenStackService):
    service = "event"
    openstack_chart = "panko"
    available_releases = ["openstack-panko"]


class Ceilometer(OpenStackService):
    service = "metering"
    openstack_chart = "ceilometer"
    available_releases = ["openstack-ceilometer"]

    def template_args(self):
        t_args = super().template_args()
        if "event" in self.mspec["features"].get("services", []):
            panko_secret = secrets.OpenStackServiceSecret(
                self.namespace, "event"
            )
            panko_secret.wait()
            panko_creds = panko_secret.get()
            t_args["event_credentials"] = panko_creds

        if "object-storage" in self.mspec["features"].get("services", []):
            kube.wait_for_secret(
                settings.OSCTL_CEPH_SHARED_NAMESPACE,
                ceph_api.OPENSTACK_KEYS_SECRET,
            )
            for rgw_key in [
                "rgw_internal_cacert",
                "rgw_metrics_user_secret_key",
                "rgw_metrics_user_access_key",
            ]:
                rgw_value = secrets.get_secret_data(
                    settings.OSCTL_CEPH_SHARED_NAMESPACE,
                    ceph_api.OPENSTACK_KEYS_SECRET,
                ).get(rgw_key)
                if rgw_value:
                    rgw_decoded = base64.b64decode(rgw_value).decode()
                    t_args[rgw_key] = rgw_decoded

        return t_args


class Gnocchi(OpenStackService):
    service = "metric"
    openstack_chart = "gnocchi"
    available_releases = ["openstack-gnocchi"]

    def template_args(self):
        t_args = super().template_args()

        t_args["redis_namespace"] = settings.OSCTL_REDIS_NAMESPACE

        redis_secret = secrets.RedisSecret(settings.OSCTL_REDIS_NAMESPACE)
        kube.wait_for_secret(
            settings.OSCTL_REDIS_NAMESPACE, redis_secret.secret_name
        )
        redis_creds = redis_secret.get()
        t_args["redis_secret"] = redis_creds.password

        return t_args


# OPENSTACK SERVICES


class Barbican(OpenStackService):
    service = "key-manager"
    openstack_chart = "barbican"
    available_releases = ["openstack-barbican-rabbitmq", "openstack-barbican"]
    _secret_class = secrets.BarbicanSecret


class Cinder(OpenStackServiceWithCeph, MaintenanceApiMixin):
    service = "block-storage"
    openstack_chart = "cinder"
    available_releases = [
        "openstack-cinder-rabbitmq",
        "openstack-iscsi",
        "openstack-cinder",
    ]

    @property
    def is_ceph_enabled(self):
        # NOTE(vsaienko): it is not allowed to configure ceph via node overrides.
        return utils.get_in(
            self.mspec, ["features", "cinder", "volume", "enabled"], True
        )

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        upgrade_map = [
            ("Job", "cinder-db-sync"),
            ("StatefulSet", "cinder-scheduler"),
        ]

        if utils.get_in(
            self.mspec, ["features", "cinder", "volume", "enabled"], True
        ):
            upgrade_map.append(("StatefulSet", "cinder-volume"))
        if utils.get_in(
            self.mspec, ["features", "cinder", "backup", "enabled"], True
        ):
            upgrade_map.append(("StatefulSet", "cinder-backup"))
        upgrade_map.extend(
            [("Deployment", "cinder-api"), ("Job", "cinder-db-sync-online")]
        )
        for kind, obj_name in upgrade_map:
            child_obj = self.get_child_object(kind, obj_name)
            if kind == "Job":
                await child_obj.purge()
            await child_obj.enable(self.openstack_version, True)

    async def remove_node_from_scheduling(self, node):
        try:
            os_client = openstack_utils.OpenStackClientManager()
            volume_services = os_client.volume_get_services(
                host=node.name, binary="cinder-volume"
            )
            if len(volume_services) > 0:
                os_client.volume_ensure_service_disabled(
                    host=node.name,
                    binary="cinder-volume",
                    disabled_reason=openstack_utils.VOLUME_SERVICE_DISABLED_REASON,
                )
            else:
                LOG.info(f"Did not found block storage services on the host.")
        except exceptions.SDKException as e:
            nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
            LOG.error(f"Cannot execute openstack commands, error: {e}")
            msg = (
                "Can not disable block-storage service on a host to be deleted"
            )
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def prepare_node_for_reboot(self, node):
        pass

    async def prepare_node_after_reboot(self, node):
        pass

    async def add_node_to_scheduling(self, node):
        try:
            os_client = openstack_utils.OpenStackClientManager()
            volume_services = os_client.volume_get_services(
                host=node.name, binary="cinder-volume"
            )
            if len(volume_services) > 0:
                volume_service = volume_services[0]
                if (
                    volume_service["disabled_reason"]
                    == openstack_utils.VOLUME_SERVICE_DISABLED_REASON
                ):
                    os_client.volume_ensure_service_enabled(
                        host=node.name,
                        binary="cinder-volume",
                    )
            else:
                LOG.info(f"Did not found block storage services on the host.")
        except exceptions.SDKException as e:
            nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
            LOG.error(f"Cannot execute openstack commands, error: {e}")
            msg = f"Can not enable block-storage service on the host {node.name}."
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def process_ndr(self, node, nwl):
        await self.remove_node_from_scheduling(node)
        if not CONF.getboolean("maintenance", "ndr_skip_volume_check"):
            os_client = openstack_utils.OpenStackClientManager()
            volumes = os_client.volume_get_volumes(host=node.name)
            volumes = [x["id"] for x in volumes]
            if volumes:
                msg = f"Some volumes {volumes} are still present on host {node.name}. Blocking node removal unless they removed or migrated."
                nwl.set_error_message(msg)
                raise kopf.TemporaryError(msg)

    async def cleanup_metadata(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        os_client = openstack_utils.OpenStackClientManager()

        def wait_for_services_down():
            volume_services = os_client.volume_get_services(
                host=node_name, binary="cinder-volume"
            )
            if len(volume_services) > 0:
                up_services = [
                    svc
                    for svc in volume_services
                    if svc["state"].lower() == "up"
                ]
                if up_services:
                    return False
            return True

        await asyncio.wait_for(
            utils.async_retry(wait_for_services_down),
            timeout=300,
        )

        cinder_api_pod = list(
            kube.resource_list(
                kube.Pod,
                {"application": "cinder", "component": "api"},
                self.namespace,
            )
        )[0]
        for svc in os_client.volume_get_services(
            host=node_name, binary="cinder-volume"
        ):
            cinder_api_pod.exec(
                [
                    "cinder-manage",
                    "service",
                    "remove",
                    "cinder-volume",
                    svc["host"],
                ],
                "cinder-api",
            )


class Cloudprober(Service):
    service = "cloudprober"
    available_releases = ["openstack-cloudprober"]

    @property
    def health_groups(self):
        return [self.service]

    def _get_keystone_creds(self):
        # TODO: use read-only admin account when it will be implemented
        account = "osctl"
        secret_class = Service.registry["identity"](
            self.mspec, self.logger, self.osdplst, self.child_view
        ).service_secret
        secret_class.wait()
        return {"cloudprober": secret_class.get().identity[account]}

    def template_args(self):
        t_args = super().template_args()
        t_args["keystone_creds"] = self._get_keystone_creds()
        return t_args


class DynamicResourceBalancer(Service):
    service = "dynamic-resource-balancer"
    available_releases = ["openstack-drb-controller"]
    openstack_chart = "drb-controller"
    _service_accounts = ["drb-controller"]
    _secret_class = secrets.DRBServiceSecret

    def template_args(self):
        template_args = super().template_args()

        admin_creds = self._get_admin_creds()
        keystone_creds = {}
        template_args.update(
            {
                "admin_creds": admin_creds,
                "keystone_creds": keystone_creds,
            }
        )
        return template_args


class Stepler(OpenStackService):
    service = "stepler"
    available_releases = ["openstack-stepler"]

    # ovveride health_groups to skip tempest during upgrade
    @property
    def health_groups(self):
        return []


class Designate(OpenStackService):
    service = "dns"
    backend_service = "powerdns"
    openstack_chart = "designate"
    available_releases = ["openstack-designate"]

    def template_args(self):
        t_args = super().template_args()
        power_dns_secret = secrets.PowerDNSSecret(self.namespace)
        power_dns_secret.ensure()
        t_args[self.backend_service] = power_dns_secret.get()

        return t_args


class Glance(OpenStackServiceWithCeph):
    service = "image"
    openstack_chart = "glance"
    available_releases = ["openstack-glance-rabbitmq", "openstack-glance"]

    @property
    def is_ceph_enabled(self):
        return "rbd" in utils.get_in(
            self.mspec, ["features", "glance", "backends"], {"rbd": {}}
        )

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        upgrade_map = [
            ("Job", "glance-db-expand"),
            ("Job", "glance-db-migrate"),
            ("Deployment", "glance-api"),
            ("Job", "glance-db-contract"),
        ]
        for kind, obj_name in upgrade_map:
            child_obj = self.get_child_object(kind, obj_name)
            await child_obj.enable(self.openstack_version, True)


class Heat(OpenStackService):
    service = "orchestration"
    openstack_chart = "heat"
    available_releases = ["openstack-heat-rabbitmq", "openstack-heat"]
    _service_accounts = ["heat_trustee", "heat_stack_user"]
    _protected_accounts = ["heat_trustee"]

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        upgrade_map = [
            ("Job", "heat-db-sync"),
            ("Deployment", "heat-api"),
            ("Deployment", "heat-cfn"),
            ("Deployment", "heat-engine"),
        ]

        extra_values = {
            "endpoints": {
                "oslo_messaging": {
                    "path": self.get_chart_value_or_none(
                        self.openstack_chart,
                        ["endpoints", "oslo_messaging", "path"],
                        self.openstack_version,
                    )
                }
            }
        }

        # NOTE(vsaienko): we update endpoints which update configmap-etc hash
        # so all heat jobs are affected. We need to purge them before doing
        # first apply.
        for resource in self.child_objects:
            if resource.immutable:
                await resource.purge()

        for kind, obj_name in upgrade_map:
            child_obj = self.get_child_object(kind, obj_name)
            if kind == "Job":
                await child_obj.purge()
            await child_obj.enable(self.openstack_version, True, extra_values)

    def template_args(self):
        t_args = super().template_args()

        # Get Tungsten Fabric API endpoint
        if (
            utils.get_in(self.mspec["features"], ["neutron", "backend"])
            == "tungstenfabric"
        ):
            kube.wait_for_secret(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )
            tf_secret = secrets.get_secret_data(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )
            tf_api_keys = ["tf_api_service", "tf_api_port"]
            if all([k in tf_secret for k in tf_api_keys]):
                t_args.update(
                    {
                        key: base64.b64decode(tf_secret[key]).decode()
                        for key in tf_api_keys
                    }
                )

        return t_args


class Horizon(OpenStackService, FederationMixin):
    service = "dashboard"
    openstack_chart = "horizon"
    available_releases = ["openstack-horizon"]
    _secret_class = secrets.HorizonSecret

    @property
    def _child_generic_objects(self):
        return {"horizon": {"job_db_init", "job_db_sync", "job_db_drop"}}

    def template_args(self):
        t_args = super().template_args()

        if "object-storage" in self.mspec["features"].get("services", []):
            kube.wait_for_secret(
                settings.OSCTL_CEPH_SHARED_NAMESPACE,
                ceph_api.OPENSTACK_KEYS_SECRET,
            )
            rgw_internal_cacert = secrets.get_secret_data(
                settings.OSCTL_CEPH_SHARED_NAMESPACE,
                ceph_api.OPENSTACK_KEYS_SECRET,
            ).get("rgw_internal_cacert")
            if rgw_internal_cacert:
                rgw_internal_cacert = base64.b64decode(
                    rgw_internal_cacert
                ).decode()
                t_args["rgw_internal_cacert"] = rgw_internal_cacert
        t_args["os_policy_services"] = constants.OS_POLICY_SERVICES.values()
        t_args.update(self.get_federation_args())

        return t_args


class Ironic(OpenStackService):
    service = "baremetal"
    openstack_chart = "ironic"
    available_releases = ["openstack-ironic-rabbitmq", "openstack-ironic"]

    @property
    def required_accounts(self):
        return {
            "networking": ["neutron"],
            "image": ["glance"],
            "compute": ["nova"],
        }


class Keystone(OpenStackService, FederationMixin):
    service = "identity"
    openstack_chart = "keystone"
    available_releases = ["openstack-keystone"]
    _service_accounts = ["osctl"]

    def _get_federation_args(self):
        federation = self.get_federation_args()
        providers = (
            federation.get("federation", {})
            .get("openid", {})
            .get("providers", {})
        )
        if providers.get("keycloak", {}).get("enabled"):
            public_domain = self.mspec["public_domain_name"]
            redirect_uris_keycloak = [
                f"{self.federation_redirect_uri}",
                f"https://horizon.{public_domain}/*",
            ]
            keycloak_provider = providers["keycloak"]
            # Create openstack IAM shared secret
            iam_secret = secrets.IAMSecret(self.namespace)
            iam_data = secrets.OpenStackIAMData(
                clientId=keycloak_provider["metadata"]["client"]["client_id"],
                redirectUris=redirect_uris_keycloak,
            )
            iam_secret.save(iam_data)
        return federation

    def _get_object_storage_args(self):
        args = {}
        # Get internal RGW secret
        kube.wait_for_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE,
            ceph_api.OPENSTACK_KEYS_SECRET,
        )
        rgw_internal_cacert = secrets.get_secret_data(
            settings.OSCTL_CEPH_SHARED_NAMESPACE,
            ceph_api.OPENSTACK_KEYS_SECRET,
        ).get("rgw_internal_cacert")
        if rgw_internal_cacert:
            rgw_internal_cacert = base64.b64decode(
                rgw_internal_cacert
            ).decode()
            args["rgw_internal_cacert"] = rgw_internal_cacert
        return args

    def _get_keystone_args(self):
        args = {}
        # Ensure the secrets with credentials/fernet keys exists
        fernet_secret_name = "keystone-fernet-data"
        credentials_secret_name = "keystone-credential-data"
        args["fernet_secret_name"] = fernet_secret_name
        args["credentials_secret_name"] = credentials_secret_name

        for secret_names in [
            ("keystone-fernet-keys", fernet_secret_name),
            ("keystone-credential-keys", credentials_secret_name),
        ]:
            LOG.info(f"Handling secret {secret_names}")
            old_secret, new_secret = secret_names

            try:
                kube.find(
                    kube.Secret,
                    name=new_secret,
                    namespace=self.namespace,
                    silent=False,
                )
            except pykube.exceptions.ObjectDoesNotExist:
                LOG.debug(f"The {new_secret} does not exists")
                data = {}
                try:
                    old_secret_obj = kube.find(
                        kube.Secret,
                        name=old_secret,
                        namespace=self.namespace,
                        silent=False,
                    )
                    data = old_secret_obj.obj["data"]
                except pykube.exceptions.ObjectDoesNotExist:
                    LOG.debug(f"The {old_secret} does not exists")

                kube.save_secret_data(
                    namespace=self.namespace, name=new_secret, data=data
                )
                LOG.debug(
                    f"Secret {new_secret} has been created successfully."
                )
        return args

    def template_args(self):
        t_args = super().template_args()
        t_args.update(self._get_keystone_args())
        t_args.update(self._get_federation_args())

        if "object-storage" in self.mspec.get("features", {}).get(
            "services", []
        ):
            t_args.update(self._get_object_storage_args())

        return t_args

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        upgrade_map = [
            ("Job", "keystone-db-sync-expand"),
            ("Job", "keystone-db-sync-migrate"),
            ("Deployment", "keystone-api"),
            ("Job", "keystone-db-sync-contract"),
        ]
        for kind, obj_name in upgrade_map:
            child_obj = self.get_child_object(kind, obj_name)
            await child_obj.enable(self.openstack_version, True)


class Neutron(OpenStackService, MaintenanceApiMixin):
    service = "networking"
    openstack_chart = "neutron"
    available_releases = [
        "openstack-neutron-rabbitmq",
        "openstack-openvswitch",
        "openstack-neutron-frrouting",
        "openstack-ipsec",
        "openstack-neutron",
    ]
    _secret_class = secrets.NeutronSecret

    @property
    def required_accounts(self):
        r_accounts = {}
        if self.is_service_enabled("dns"):
            r_accounts["dns"] = ["designate"]
        compute_accounts = ["nova"]
        if self.openstack_version in [
            "queens",
            "rocky",
        ]:
            compute_accounts.append("placement")
        else:
            r_accounts["placement"] = ["placement"]

        r_accounts["compute"] = compute_accounts
        if self.is_service_enabled("baremetal"):
            r_accounts["baremetal"] = ["ironic"]
        return r_accounts

    def template_args(self):
        t_args = super().template_args()

        ngs_ssh_keys = {}
        if "baremetal" in self.mspec["features"]["services"]:
            for device in (
                self.mspec["features"]
                .get("neutron", {})
                .get("baremetal", {})
                .get("ngs", {})
                .get("devices", [])
            ):
                if "ssh_private_key" in device:
                    ngs_ssh_keys[f"{device['name']}_ssh_private_key"] = device[
                        "ssh_private_key"
                    ]
            for device_name, device in (
                self.mspec["features"]
                .get("neutron", {})
                .get("baremetal", {})
                .get("ngs", {})
                .get("hardware", {})
                .items()
            ):
                if "ssh_private_key" in device:
                    ngs_ssh_keys[f"{device_name}_ssh_private_key"] = device[
                        "ssh_private_key"
                    ]
        if ngs_ssh_keys:
            ngs_secret = secrets.NgsSSHSecret(self.namespace)
            ngs_secret.save(ngs_ssh_keys)

        # Get Tungsten Fabric API endpoint
        if (
            utils.get_in(self.mspec["features"], ["neutron", "backend"])
            == "tungstenfabric"
        ):
            kube.wait_for_secret(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )
            tf_secret = secrets.get_secret_data(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )

            tf_api_keys = ["tf_api_service", "tf_api_port"]
            if all([k in tf_secret for k in tf_api_keys]):
                t_args.update(
                    {
                        key: base64.b64decode(tf_secret[key]).decode()
                        for key in tf_api_keys
                    }
                )
        if (
            utils.get_in(
                self.mspec["features"], ["neutron", "bgpvpn", "enabled"]
            )
            == True
            and utils.get_in(
                self.mspec["features"], ["neutron", "bgpvpn", "peers"]
            )
            == None
        ):
            neighbors_secret = secrets.BGPVPNSecret()
            peers = []
            # NOTE(vsaienko) we deploy frr with networking helmbundle, so render
            # first with empty peers, which will be updated once frr chart create
            # secret
            if neighbors_secret.kube_obj.exists():
                peers = neighbors_secret.get_peer_ips()
            t_args["bgpvpn_reflector_peers"] = peers

        return t_args

    @property
    def health_groups(self):
        health_groups = [self.openstack_chart]
        neutron_backend = utils.get_in(
            self.mspec["features"], ["neutron", "backend"]
        )
        if neutron_backend == "ml2":
            health_groups.append("openvswitch")
        elif neutron_backend == "ml2/ovn":
            health_groups.append("openvswitch_ovn")

        return health_groups

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        neutron_server_deployment_type = "Deployment"
        if (
            utils.get_in(self.mspec, ["features", "neutron", "backend"])
            == "ml2/ovn"
        ):
            neutron_server_deployment_type = "DaemonSet"
        static_map = [
            ("Job", "neutron-db-sync"),
            (neutron_server_deployment_type, "neutron-server"),
        ]

        dynamic_map = [
            ("DaemonSet", "neutron-sriov-agent"),
            ("DaemonSet", "neutron-ovs-agent"),
        ]
        if (
            utils.get_in(self.mspec["features"], ["neutron", "backend"])
            != "tungstenfabric"
        ):
            dynamic_map = {}

        for kind, obj_name in static_map:
            child_obj = self.get_child_object(kind, obj_name)
            if kind == "Job":
                await child_obj.purge()
            await child_obj.enable(self.openstack_version, True)

        for kind, abstract_name in dynamic_map:
            child_objs = self.get_child_objects_dynamic(kind, abstract_name)
            for child_obj in child_objs:
                await child_obj.enable(self.openstack_version, True)

    async def _upgrade_ovn(self, event, **kwargs):
        """Perform OVN upgrade to major version

        For OVN we use the following upgrade order:

        1. Upgrade of ovn-conroller on computes and gateways
        2. Upgrade of ovn-sb, ovn-nb
        3. Upgrade of ovn-northd
        4. neutron-server upgrade/restart
        """

        def _extract_ovs_version(image):
            try:
                return image.split(":")[-1].split("-")[0]
            except Exception:
                return None

        new_ovn_image = self.get_image(
            "openvswitch_ovn_db_nb", "openvswitch", self.openstack_version
        )
        old_ovn_image = (
            (
                await self.helm_manager.get_release_values(
                    "openstack-openvswitch"
                )
            )
            .get("images", {})
            .get("tags", {})
            .get("openvswitch_ovn_db_nb")
        )
        new_ovn_image = _extract_ovs_version(new_ovn_image)
        old_ovn_image = _extract_ovs_version(old_ovn_image)

        # Apply new startap scripts, but do not change images
        # this is needed when custom startup flags are
        # passed to service
        if old_ovn_image != new_ovn_image:
            LOG.info(
                f"OVN upgrade: image was changed, initiating update from {old_ovn_image} to {new_ovn_image}"
            )
            timestamp = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            LOG.info(
                "OVN upgrade: updating deploy scripts for OVN components."
            )
            await self.set_release_values(
                "openvswitch",
                {
                    f"{self.group}/{self.version}": {
                        "rockoon": {"updated_at": timestamp}
                    }
                },
            )
            await asyncio.sleep(
                CONF.getint("helmbundle", "manifest_apply_delay")
            )
            ovndb_sts = self.get_child_object(
                "StatefulSet", "openvswitch-ovn-db"
            )
            await ovndb_sts.wait_ready()
            await self.wait_service_healthy()

            for ovnc_ds in self.get_child_objects_dynamic(
                "DaemonSet", "ovn-controller"
            ):
                # TODO(vsaienko): fix need_apply_images for multiple child objects
                if ovnc_ds.need_apply_images(self.openstack_version):
                    LOG.info(
                        "OVN upgrade: updating image for ovn-controllers."
                    )
                    await ovnc_ds.enable(
                        self.openstack_version,
                        wait_completion=True,
                        timeout=None,
                    )
                await ovnc_ds.ensure_pod_generation()
                await ovnc_ds.wait_ready()
            ovndb_sts = self.get_child_object(
                "StatefulSet", "openvswitch-ovn-db"
            )
            if ovndb_sts.need_apply_images(self.openstack_version):
                LOG.info("OVN upgrade: updating image for ovn-dbs.")
                await ovndb_sts.enable(
                    self.openstack_version,
                    wait_completion=True,
                    timeout=None,
                )
                await ovndb_sts.wait_ready()

            ovnnb_sts = self.get_child_object(
                "StatefulSet", "openvswitch-ovn-northd"
            )

            if ovnnb_sts.need_apply_images(self.openstack_version):
                LOG.info("OVN upgrade: scaling ovn-northd to 0.")
                ovnnb_sts.scale(0)
                await ovnnb_sts.wait_for_replicas(0)

                # Restart db pods to remove flags set before running update
                # like --disable-file-no-data-conversion
                LOG.info("OVN upgrade: restarting ovn-dbs.")
                ovndb_sts.restart()

                await ovndb_sts.wait_ready()

                await ovnnb_sts.enable(
                    self.openstack_version,
                    wait_completion=True,
                    timeout=None,
                )

                await ovnnb_sts.wait_ready()
                await self.wait_service_healthy()
            LOG.info("OVN upgrade: finished")
            # With later super().apply() neutron-server will be retarted.

    async def apply(self, event, **kwargs):
        if (
            self.mspec.get("migration", {})
            .get("neutron", {})
            .get("deploy_main_service", True)
        ):
            neutron_features = self.mspec["features"].get("neutron", {})
            if neutron_features.get("backend", "") == "tungstenfabric":
                ssl_public_endpoints = (
                    self.mspec["features"]
                    .get("ssl", {})
                    .get("public_endpoints", {})
                )
                octavia_mgmt_network = utils.get_in(
                    self.mspec["features"],
                    ["octavia", "lb_network"],
                    {
                        "subnets": [
                            {
                                "range": "10.255.0.0/16",
                                "pool_start": "10.255.1.0",
                                "pool_end": "10.255.255.254",
                            }
                        ]
                    },
                )
                octavia_mgmt_network.setdefault("name", "lb-mgmt-net")
                b64encode = lambda v: base64.b64encode(v.encode()).decode()
                secret_data = {
                    "tunnel_interface": b64encode(
                        neutron_features.get("tunnel_interface", "")
                    ),
                    "public_domain": b64encode(
                        self.mspec["public_domain_name"]
                    ),
                    "certificate_authority": b64encode(
                        ssl_public_endpoints.get("ca_cert")
                    ),
                    "certificate": b64encode(
                        ssl_public_endpoints.get("api_cert")
                    ),
                    "private_key": b64encode(
                        ssl_public_endpoints.get("api_key")
                    ),
                    "ingress_namespace_class": b64encode(
                        utils.get_in(
                            self.mspec["services"],
                            [
                                "ingress",
                                "ingress",
                                "values",
                                "deployment",
                                "cluster",
                                "class",
                            ],
                            "nginx-cluster",
                        )
                    ),
                    "octavia_mgmt_network": b64encode(
                        json.dumps(octavia_mgmt_network)
                    ),
                }

                nodes = {}
                if self.mspec.get("nodes"):
                    for label_key in self.mspec["nodes"]:
                        if utils.get_in(
                            self.mspec["nodes"][label_key],
                            ["features", "neutron"],
                        ):
                            nodes[label_key] = utils.get_in(
                                self.mspec["nodes"][label_key],
                                ["features", "neutron"],
                            )
                secret_data["nodes"] = b64encode(json.dumps(nodes))

                tfs = secrets.TungstenFabricSecret()
                tfs.save(secret_data)

            # NOTE(vsaienko): Ensure l2 agents updated prior all other services.
            dynamic_map = [
                ("DaemonSet", "neutron-sriov-agent"),
                ("DaemonSet", "neutron-ovs-agent"),
            ]
            for kind, abstract_name in dynamic_map:
                child_objs = self.get_child_objects_dynamic(
                    kind, abstract_name
                )
                for child_obj in child_objs:
                    if child_obj.exists() and child_obj.need_apply_images(
                        self.openstack_version
                    ):
                        await child_obj.enable(
                            self.openstack_version,
                            wait_completion=True,
                            timeout=None,
                        )

        if (
            utils.get_in(self.mspec["features"], ["neutron", "backend"])
            == "ml2/ovn"
        ):
            await self._upgrade_ovn(event, **kwargs)

        await super().apply(event, **kwargs)
        if utils.get_in(
            self.mspec["features"], ["neutron", "backend"]
        ) == "ml2" and self.service in utils.get_in(
            self.mspec["features"],
            ["messaging", "components_with_dedicated_messaging"],
            [],
        ):
            rabbitmq_sts = self.get_child_object(
                "StatefulSet", "openstack-neutron-rabbitmq-rabbitmq"
            )
            await rabbitmq_sts.wait_ready(interval=30)
        cmr = kube.ClusterMaintenanceRequest.objects(
            kube.kube_client()
        ).get_or_none()
        # NOTE(vsaienko): if cluster under maintenance postpone restart when nodemaintenancerequests
        # are removed.
        # NOTE(mkarpin): if cluster in process of migration from OVS to OVN neutron backend - do
        # not update dataplane related daemonsets.
        if not cmr and not utils.get_in(
            self.mspec, ["migration", "neutron", "ovs_ovn_migration"]
        ):
            # Restart openvswitch daemonsets
            # Prevent restarting l3 agents simulteniously with openvswitch
            for daemonset in [
                "ovn-controller",
                "openvswitch-vswitchd",
                "neutron-l3-agent",
            ]:
                for ovs_ds in self.get_child_objects_dynamic(
                    "DaemonSet", daemonset
                ):
                    await ovs_ds.ensure_pod_generation()

    async def remove_node_from_scheduling(self, node):
        pass

    async def prepare_node_for_reboot(self, node):
        pass

    async def prepare_node_after_reboot(self, node):
        if (
            utils.get_in(self.mspec["features"], ["neutron", "backend"])
            == "tungstenfabric"
        ):
            return
        neutron_roles = [
            constants.NodeRole.compute,
            constants.NodeRole.gateway,
        ]
        all_neutron_roles = []
        for role in neutron_roles:
            all_neutron_roles.append(node.has_role(role))
        if not any(all_neutron_roles):
            return

        nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)

        # Restart openvswitch daemonsets
        for daemonset in [
            "ovn-controller",
            "openvswitch-vswitchd",
            "neutron-l3-agent",
        ]:
            for ovs_ds in self.get_child_objects_dynamic(
                "DaemonSet", daemonset
            ):
                await ovs_ds.ensure_pod_generation_on_node(node.name)
        try:
            os_client = openstack_utils.OpenStackClientManager()

            def wait_for_agents_up():
                network_agents = os_client.network_get_agents(
                    host=node.name, is_alive=False
                )
                network_agents = [a.id for a in network_agents]
                if network_agents:
                    return False
                return True

            try:
                await asyncio.wait_for(
                    utils.async_retry(wait_for_agents_up),
                    timeout=300,
                )
            except asyncio.TimeoutError:
                msg = f"Timeout waiting for network agents on the host {node.name}."
                nwl.set_error_message(msg)
                raise kopf.TemporaryError(msg)
        except openstack.exceptions.SDKException as e:
            msg = f"Got error while waiting for network agents. Cannot execute openstack commands, error: {e}."
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def add_node_to_scheduling(self, node):
        pass

    async def process_ndr(self, node, nwl):
        return await self.remove_node_from_scheduling(node)

    async def cleanup_metadata(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        os_client = openstack_utils.OpenStackClientManager()
        await os_client.network_wait_agent_state(
            host=node_name, is_alive=False
        )
        os_client.network_ensure_agents_absent(host=node_name)


class Nova(OpenStackServiceWithCeph, MaintenanceApiMixin):
    service = "compute"
    openstack_chart = "nova"
    available_releases = [
        "openstack-nova-rabbitmq",
        "openstack-libvirt",
        "openstack-nova",
    ]

    @property
    def service_accounts(self):
        s_accounts = super().service_accounts
        if self.openstack_version in [
            "queens",
            "rocky",
        ]:
            s_accounts.append("placement")
        return s_accounts

    @property
    def required_accounts(self):
        r_accounts = {
            "networking": ["neutron"],
            "identity": ["osctl"],
        }
        if self.is_service_enabled("block-storage"):
            r_accounts["block-storage"] = ["cinder"]
        if self.openstack_version not in [
            "queens",
            "rocky",
        ]:
            r_accounts["placement"] = ["placement"]
        services = self.mspec["features"]["services"]
        if "baremetal" in services:
            r_accounts["baremetal"] = ["ironic"]
        return r_accounts

    def template_args(self):
        t_args = super().template_args()

        ssh_secret = secrets.SSHSecret(self.namespace, "nova")
        ssh_secret.ensure()
        t_args["ssh_credentials"] = ssh_secret.get()

        neutron_secret = secrets.NeutronSecret(self.namespace, "networking")
        neutron_secret.wait()
        neutron_creds = neutron_secret.get()

        t_args["metadata_secret"] = neutron_creds.metadata_secret

        neutron_features = self.mspec["features"].get("neutron", {})

        # Generare CA certs for libvirt server
        if utils.get_in(
            self.mspec,
            ["features", "nova", "libvirt", "tls", "enabled"],
            False,
        ):
            libvirt_cert_secret = secrets.SignedCertificateSecret(
                self.namespace,
                constants.LIBVIRT_SERVER_TLS_SECRET_NAME,
                "libvirt-server",
            )
            libvirt_cert_secret.ensure()
            libvirt_certs = libvirt_cert_secret.get()
            t_args["libvirt_certs"] = libvirt_certs

        # Generare server-side certs for VNC TLS
        vnc_cert_secret = secrets.SignedCertificatePackSecret(
            self.namespace,
            "libvirt-vnc-tls",
            f"*.{self.mspec['internal_domain_name']}",
            f"*.{self.mspec['public_domain_name']}",
        )
        vnc_cert_secret.ensure()
        libvirt_vnc_certs = vnc_cert_secret.get()
        t_args["libvirt_vnc_certs"] = libvirt_vnc_certs

        # Read secret from shared namespace with TF deployment to
        # get value of vrouter port for setting it as env variable
        # in nova-compute container
        if neutron_features.get("backend", "") == "tungstenfabric":
            kube.wait_for_secret(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )
            vrouter_port = base64.b64decode(
                secrets.get_secret_data(
                    constants.OPENSTACK_TF_SHARED_NAMESPACE,
                    constants.TF_OPENSTACK_SECRET,
                )["vrouter_port"]
            ).decode()

            t_args["vrouter_port"] = vrouter_port

        return t_args

    @property
    def is_ceph_enabled(self):
        if self.is_service_enabled("block-storage") and utils.get_in(
            self.mspec, ["features", "cinder", "volume", "enabled"], True
        ):
            return True
        if (
            utils.get_in(self.mspec, ["features", "nova", "images", "backend"])
            == "ceph"
        ):
            return True
        for label, options in self.mspec.get("nodes", {}).items():
            if (
                utils.get_in(
                    options, ["features", "nova", "images", "backend"]
                )
                == "ceph"
            ):
                return True
        return False

    @layers.kopf_exception
    async def _upgrade(self, event, **kwargs):
        upgrade_map = [
            ("Job", "nova-db-sync-api"),
            ("Job", "nova-db-sync-db"),
            ("Job", "nova-db-sync"),
        ]
        for kind, obj_name in upgrade_map:
            child_obj = self.get_child_object(kind, obj_name)
            await child_obj.purge()
            await child_obj.enable(self.openstack_version, True)

    async def can_handle_nmr(self, node, locks):
        if not node.has_role(constants.NodeRole.compute):
            return True
        if not CONF.getboolean("maintenance", "respect_nova_az"):
            LOG.info(
                "The maintenance:respect_nova_az is set to False. Skip availability zones."
            )
            return True
        os_client = openstack_utils.OpenStackClientManager()
        node_az = os_client.compute_get_services(
            host=node.name, binary="nova-compute"
        )[0].location.zone

        if len(locks[constants.NodeRole.compute.value]) == 0:
            return True

        # NOTE(vsaienko): assume we do maintenance for host in same AZ
        nwl = locks[constants.NodeRole.compute.value][0]
        hostname = nwl.obj["spec"]["nodeName"]
        nwl_host_az = os_client.compute_get_services(
            host=hostname, binary="nova-compute"
        )[0].location.zone

        if node_az is None:
            LOG.info(f"Can't find AZ for one of nodes {hostname}, {node.name}")
            return True

        if node_az != nwl_host_az:
            LOG.info(
                f"Do not allow handline nmr for node: {node.name}. Node az {node_az} does not match hosts that currently in maintenance {nwl_host_az}"
            )
            return False
        return True

    async def remove_node_from_scheduling(self, node):
        nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
        if not node.has_role(constants.NodeRole.compute):
            return
        try:
            os_client = openstack_utils.OpenStackClientManager()
            target_service = os_client.compute_get_services(host=node.name)[0]
            os_client.compute_ensure_service_disabled(
                target_service,
                disabled_reason=openstack_utils.COMPUTE_SERVICE_DISABLE_REASON,
            )
        except exceptions.SDKException as e:
            LOG.error(f"Cannot execute openstack commands, error: {e}")
            msg = "Can not disable compute service on a host to be deleted"
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def _migrate_servers(self, os_client, host, cfg, nwl, concurrency=1):
        async def _check_migration_completed(node_migration_mode):
            all_servers = os_client.compute_get_all_servers(host=host)
            all_servers = [
                s
                for s in all_servers
                if s.vm_state
                not in openstack_utils.SERVER_STATES_SAFE_FOR_REBOOT
            ]

            # Filter servers by power state
            all_servers = [
                s
                for s in all_servers
                if s.power_state
                not in openstack_utils.SERVER_STOPPED_POWER_STATES
            ]

            # Exclude servers that can be powered off
            all_servers = [
                s
                for s in all_servers
                if os_client.compute_get_server_maintenance_action(
                    s, node_migration_mode
                )
                != "poweroff"
            ]
            if all_servers:
                to_notify = []
                other_servers = []
                for s in all_servers:
                    server_maintenance_action = (
                        os_client.compute_get_server_maintenance_action(
                            s, node_migration_mode
                        )
                    )
                    if server_maintenance_action == "notify":
                        to_notify.append(s.id)
                    else:
                        other_servers.append(s.id)
                msg = "Some servers are still present on the host."
                if to_notify:
                    msg += (
                        f" Notify owners of the following server: {to_notify}"
                    )
                if other_servers:
                    msg += f" Servers with unset maintenance action: {other_servers}"
                nwl.set_error_message(msg)
                raise kopf.TemporaryError(msg)

        async def _do_servers_migration(node_migration_mode):
            servers_to_migrate = (
                os_client.compute_get_servers_valid_for_live_migration(
                    host=host, node_migration_mode=node_migration_mode
                )
            )
            servers_migrating_count = {}
            while servers_to_migrate:
                LOG.info(
                    f"Got servers to migrate {[s.id for s in servers_to_migrate]}"
                )
                servers_in_migrating_state = (
                    os_client.compute_get_servers_in_migrating_state(host=host)
                )
                if len(servers_in_migrating_state) < concurrency:
                    random.shuffle(servers_to_migrate)
                    srv = servers_to_migrate.pop()
                    msg = f"Starting migration for {srv.id}"
                    LOG.info(msg)
                    nwl.set_error_message(msg)
                    try:
                        servers_migrating_count[srv.id] = (
                            servers_migrating_count.get(srv.id, 1) + 1
                        )
                        os_client.oc.compute.live_migrate_server(srv)
                        # NOTE(vsaienko): do not call API extensively, give some time for API
                        # to set correct status for instance.
                        await asyncio.sleep(5)
                    except Exception as e:
                        msg = f"Got error while trying to migrate server {srv.id}: {e}"
                        LOG.warning(msg)
                        nwl.set_error_message(msg)
                else:
                    msg = f"Waiting servers migration is completed: {[s.id for s in servers_in_migrating_state]}"
                    LOG.info(msg)
                    nwl.set_error_message(msg)
                    await asyncio.sleep(30)
                await asyncio.sleep(5)
                servers_migrating_skip = [
                    srv_id
                    for srv_id, error_count in servers_migrating_count.items()
                    if error_count > int(cfg.instance_migration_attempts)
                ]
                servers_to_migrate = (
                    os_client.compute_get_servers_valid_for_live_migration(
                        host=host, node_migration_mode=node_migration_mode
                    )
                )
                servers_to_migrate = [
                    srv
                    for srv in servers_to_migrate
                    if srv.id not in servers_migrating_skip
                ]

        await _do_servers_migration(cfg.instance_migration_mode)
        await _check_migration_completed(cfg.instance_migration_mode)

    async def prepare_node_for_reboot(self, node):
        nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
        if not node.has_role(constants.NodeRole.compute):
            return
        maintenance_cfg = maintenance.NodeMaintenanceConfig(node)

        try:
            os_client = openstack_utils.OpenStackClientManager()
            await self._migrate_servers(
                os_client=os_client,
                host=node.name,
                cfg=maintenance_cfg,
                nwl=nwl,
                concurrency=CONF.getint(
                    "maintenance", "instance_migrate_concurrency"
                ),
            )
        except exceptions.SDKException as e:
            msg = f"Retrying migrate instances from host. Cannot execute openstack commands, error: {e}"
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def prepare_node_after_reboot(self, node):
        nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
        if not node.has_role(constants.NodeRole.compute):
            return
        try:
            os_client = openstack_utils.OpenStackClientManager()

            def wait_for_service_found_and_up():
                compute_services = os_client.compute_get_services(
                    host=node.name
                )
                states = [s.state.lower() == "up" for s in compute_services]
                if states and all(states):
                    return True
                return False

            try:
                await asyncio.wait_for(
                    utils.async_retry(wait_for_service_found_and_up),
                    timeout=300,
                )
            except asyncio.TimeoutError:
                msg = "Timeout waiting for compute services up on the host."
                nwl.set_error_message(msg)
                raise kopf.TemporaryError(msg)
        except openstack.exceptions.SDKException as e:
            msg = f"Got error while waiting services to be UP on the host. Cannot execute openstack commands, error: {e}"
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def add_node_to_scheduling(self, node):
        nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
        if not node.has_role(constants.NodeRole.compute):
            return
        try:
            os_client = openstack_utils.OpenStackClientManager()
            service = os_client.compute_get_services(host=node.name)[0]
            # Enable service, in case this is a compute that was previously
            # removed and now is being added back
            if (
                service["disabled_reason"]
                == openstack_utils.COMPUTE_SERVICE_DISABLE_REASON
            ):
                os_client.compute_ensure_service_enabled(service)
        except openstack.exceptions.SDKException as e:
            msg = f"Can not bring node back to scheduling. Cannot execute openstack commands, error: {e}"
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

    async def process_ndr(self, node, nwl):
        await self.remove_node_from_scheduling(node)
        if not CONF.getboolean("maintenance", "ndr_skip_instance_check"):
            os_client = openstack_utils.OpenStackClientManager()
            all_servers = os_client.compute_get_all_servers(host=node.name)
            servers_out = {s.id: s.status for s in all_servers}
            if servers_out:
                msg = f"Some servers {servers_out} are still present on host {node.name}. Blocking node removal unless they removed or migrated."
                nwl.set_error_message(msg)
                raise kopf.TemporaryError(msg)

    async def cleanup_metadata(self, nwl):
        node_name = nwl.obj["spec"]["nodeName"]
        os_client = openstack_utils.OpenStackClientManager()
        await os_client.compute_wait_service_state(
            host=node_name, state="down"
        )
        os_client.compute_ensure_services_absent(host=node_name)
        os_client.placement_resource_provider_absent(host=node_name)


class Placement(OpenStackService):
    service = "placement"
    openstack_chart = "placement"
    available_releases = ["openstack-placement"]

    @property
    def _child_generic_objects(self):
        return {
            "placement": {
                "job_db_init",
                "job_db_sync",
                "job_db_drop",
                "job_ks_endpoints",
                "job_ks_service",
                "job_ks_user",
            }
        }

    @layers.kopf_exception
    async def upgrade(self, event, **kwargs):
        LOG.info(f"Upgrading {self.service} started.")
        # NOTE(mkarpin): skip health check for stein release,
        # as this is first release where placement is added
        if self.mspec["openstack_version"] == "stein":
            upgrade_map = [
                ("Deployment", "nova-placement-api"),
                ("Job", "placement-ks-user"),
                ("Job", "placement-ks-service"),
                ("Job", "placement-ks-endpoints"),
                ("Service", "placement"),
                ("Service", "placement-api"),
                ("Secret", "placement-tls-public"),
                ("Ingress", "placement"),
            ]
            compute_service_instance = Service.registry["compute"](
                self.mspec, self.logger, self.osdplst, self.child_view
            )
            try:
                LOG.info(
                    f"Disabling Nova child objects related to {self.service}."
                )
                kwargs["helmobj_overrides"] = {
                    "openstack-placement": {
                        "manifests": {"job_db_nova_migrate_placement": True}
                    }
                }
                for kind, obj_name in upgrade_map:
                    child_obj = compute_service_instance.get_child_object(
                        kind, obj_name
                    )
                    await child_obj.disable(wait_completion=True)
                LOG.info(
                    f"{self.service} database migration will be performed."
                )
                await self.apply(event, **kwargs)
                # TODO(vsaienko): implement logic that will check that changes made in helmbundle
                # object were handled by tiller/helmcontroller
                # can be done only once https://mirantis.jira.com/browse/PRODX-2283 is implemented.
                await asyncio.sleep(
                    CONF.getint("helmbundle", "manifest_apply_delay")
                )
                await self.wait_service_healthy()
                # NOTE(mkarpin): db sync job should be cleaned up after upgrade and before apply
                # because placement_db_nova_migrate_placement job is in dynamic dependencies
                # for db sync job, during apply it will be removed
                LOG.info(f"Cleaning up database migration jobs")
                await self.get_child_object("Job", "placement-db-sync").purge()
                # Recreate placement-db-sync without nova_migrate_placement dependency
                kwargs.pop("helmobj_overrides")
                await self.apply(event, **kwargs)
            except Exception as e:
                # NOTE(mkarpin): in case something went wrong during placement migration
                # we need to cleanup all child objects related to placement
                # because disabling procedure  in next retry will never succeed, because
                # nova release already have all objects disabled.
                for kind, obj_name in upgrade_map:
                    child_obj = compute_service_instance.get_child_object(
                        kind, obj_name
                    )
                    await child_obj.purge()
                raise kopf.TemporaryError(f"{e}") from e
            LOG.info(f"Upgrading {self.service} done")
        else:
            await super().upgrade(event, **kwargs)


class Octavia(OpenStackService):
    service = "load-balancer"
    openstack_chart = "octavia"
    available_releases = ["openstack-octavia-rabbitmq", "openstack-octavia"]

    def template_args(self):
        t_args = super().template_args()
        cert_secret = secrets.SignedCertificateSecret(
            self.namespace, "octavia", "octavia-amphora-ca"
        )
        cert_secret.ensure()
        ssh_secret = secrets.SSHSecret(self.namespace, self.service)
        ssh_secret.ensure()
        t_args["ssh_credentials"] = ssh_secret.get()

        neutron_features = self.mspec["features"].get("neutron", {})
        if neutron_features.get("backend", "") == "tungstenfabric":
            # Get Octavia HM IPs from shared OS+TF namespace
            kube.wait_for_secret(
                constants.OPENSTACK_TF_SHARED_NAMESPACE,
                constants.TF_OPENSTACK_SECRET,
            )
            octavia_hm_list = base64.b64decode(
                secrets.get_secret_data(
                    constants.OPENSTACK_TF_SHARED_NAMESPACE,
                    constants.TF_OPENSTACK_SECRET,
                )["octavia_hm_list"]
            ).decode()
            t_args["octavia_hm_list"] = json.loads(octavia_hm_list)

        if "redis" in self.mspec["features"]["services"]:
            t_args["redis_namespace"] = settings.OSCTL_REDIS_NAMESPACE

            redis_secret = secrets.RedisSecret(settings.OSCTL_REDIS_NAMESPACE)
            kube.wait_for_secret(
                settings.OSCTL_REDIS_NAMESPACE, redis_secret.secret_name
            )
            redis_creds = redis_secret.get()
            t_args["redis_secret"] = redis_creds.password
        return t_args


class RadosGateWay(OpenStackService):
    service = "object-storage"
    available_releases = ["openstack-ceph-rgw"]

    # override health groups to skip wait for healthy service check
    # as ceph rgw contain only jobs
    @property
    def health_groups(self):
        return []

    def template_args(self):
        t_args = super().template_args()

        auth_url = (
            "http://keystone-api.openstack.svc."
            + self.mspec["internal_domain_name"]
            + ":5000"
        )
        ssl_public_endpoints = self.mspec["features"]["ssl"][
            "public_endpoints"
        ]
        # NOTE(vsaienko): share date with ceph first so it can construct correct
        # public endpoint
        if "ceph-rgw" in t_args["credentials"][0].identity.keys():
            service_cred = t_args["credentials"][0].identity["ceph-rgw"]
            rgw_creds = {
                "auth_url": auth_url,
                "default_domain": "service",
                "interface": "public",
                "password": service_cred.password,
                "project_domain_name": "service",
                "project_name": "service",
                "region_name": self.mspec.get("region_name", "RegionOne"),
                "user_domain_name": "service",
                "username": service_cred.username,
                "public_domain": self.mspec["public_domain_name"],
                "ca_cert": ssl_public_endpoints["ca_cert"],
                "tls_crt": ssl_public_endpoints["api_cert"],
                "tls_key": ssl_public_endpoints["api_key"],
                "barbican_url": "http://barbican-api.openstack.svc."
                + self.mspec["internal_domain_name"]
                + ":9311",
            }

            # encode values from rgw_creds
            for key in rgw_creds.keys():
                rgw_creds[key] = base64.b64encode(
                    rgw_creds[key].encode()
                ).decode()

            os_rgw_creds = ceph_api.OSRGWCreds(**rgw_creds)

            ceph_api.set_os_rgw_creds(
                os_rgw_creds=os_rgw_creds,
                save_secret=kube.save_secret_data,
            )
            LOG.info("Secret with RGW creds has been created successfully.")

        kube.wait_for_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE,
            ceph_api.OPENSTACK_KEYS_SECRET,
        )

        for rgw_key in ["rgw_internal", "rgw_external"]:
            rgw_url = base64.b64decode(
                secrets.get_secret_data(
                    settings.OSCTL_CEPH_SHARED_NAMESPACE,
                    ceph_api.OPENSTACK_KEYS_SECRET,
                ).get(rgw_key)
            ).decode()

            urlparsed = urlsplit(rgw_url)
            rgw_port = urlparsed.port
            if not rgw_port:
                if urlparsed.scheme == "http":
                    rgw_port = "80"
                if urlparsed.scheme == "https":
                    rgw_port = "443"

            t_args[rgw_key] = {
                "host": urlparsed.hostname,
                "port": rgw_port,
                "scheme": urlparsed.scheme,
            }

        return t_args


class Tempest(OpenStackService):
    service = "tempest"
    available_releases = ["openstack-tempest"]

    # ovveride health_groups to skip tempest during upgrade
    @property
    def health_groups(self):
        return []

    @property
    def is_ceph_enabled(self):
        return utils.get_in(
            self.mspec, ["features", "cinder", "volume", "enabled"], True
        )

    def template_args(self):
        template_args = super().template_args()

        helmbundles_body = {}
        for s in set(self.mspec["features"]["services"]) - {
            "tempest",
            "redis",
        }:
            service_template_args = Service.registry[s](
                self.mspec, self.logger, self.osdplst, self.child_view
            ).template_args()
            try:
                helmbundles_body[s] = layers.merge_all_layers(
                    s,
                    self.mspec,
                    self.logger,
                    **service_template_args,
                )
            except Exception as e:
                raise kopf.PermanentError(
                    f"Error while rendering HelmBundle for {self.service} "
                    f"service: {e}"
                )

        template_args["helmbundles_body"] = helmbundles_body
        return template_args


class Masakari(OpenStackService):
    service = "instance-ha"
    openstack_chart = "masakari"
    available_releases = ["openstack-masakari-rabbitmq", "openstack-masakari"]


class Manila(OpenStackServiceWithCeph):
    service = "shared-file-system"
    openstack_chart = "manila"
    available_releases = [
        "openstack-manila",
    ]

    @property
    def is_ceph_enabled(self):
        manila_backends = utils.get_in(
            self.mspec, ["features", "manila", "share", "backends"], {}
        )
        for opts in manila_backends.values():
            if opts.get("enabled", True):
                enabled_backends = utils.get_in(
                    opts["values"],
                    ["conf", "manila", "DEFAULT", "enabled_share_backends"],
                    "",
                ).split(",")
                for backend in enabled_backends:
                    driver = utils.get_in(
                        opts["values"],
                        ["conf", "manila", backend, "share_driver"],
                        "",
                    )
                    if (
                        driver
                        == "manila.share.drivers.cephfs.driver.CephFSDriver"
                    ):
                        return True
        return False

    def template_args(self):
        template_args = super().template_args()
        ssh_secret = secrets.SSHSecret(self.namespace, self.service)
        ssh_secret.ensure()
        template_args["ssh_credentials"] = ssh_secret.get()
        return template_args

    @property
    def required_accounts(self):
        return {
            "networking": ["neutron"],
            "block-storage": ["cinder"],
            "image": ["glance"],
            "compute": ["nova"],
        }


registry = Service.registry

# NOTE(vsaienko): keep here to avoid cyclic import with rockoon.maintenance
ORDERED_SERVICES = list(
    sorted(
        filter(
            lambda tup: tup[0] in constants.SERVICE_ORDER,
            registry.items(),
        ),
        key=lambda tup: constants.SERVICE_ORDER[tup[0]],
    )
)
