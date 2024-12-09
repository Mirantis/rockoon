from abc import abstractmethod
import asyncio
import base64
import json
from jsonpath_ng import parse
from typing import List
import hashlib

import kopf
import pykube

from rockoon import ceph_api
from rockoon import constants
from rockoon import health
from rockoon import layers
from rockoon import kube
from rockoon import secrets
from rockoon import settings
from rockoon import version
from rockoon import utils
from rockoon import helm
from rockoon.osdplstatus import APPLYING, APPLIED, DELETING


LOG = utils.get_logger(__name__)
CONF = settings.CONF


class Service:
    service = None
    group = "lcm.mirantis.com"
    version = "v1alpha1"
    kind = "HelmBundle"
    registry = {}
    available_releases = []

    _service_accounts = []
    _secret_class = None
    _protected_accounts = []

    @property
    def required_accounts(self):
        return {}

    @property
    def service_secret(self):
        """Returns instance of service _secret_class"""
        if self._secret_class is not None:
            return self._secret_class(
                self.namespace,
                self.service,
                self.service_accounts,
                self._protected_accounts,
            )

    @property
    def maintenance_api(self):
        return isinstance(self, MaintenanceApiMixin)

    @property
    def service_accounts(self) -> List[str]:
        service_name = constants.OS_SERVICES_MAP.get(self.service)
        if service_name:
            return self._service_accounts + [service_name, "test"]
        return self._service_accounts

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.registry[cls.service] = cls

    @property
    def namespace(self):
        return settings.OSCTL_OS_DEPLOYMENT_NAMESPACE

    def __init__(self, mspec, logger, osdplst, child_view):
        self.mspec = mspec
        self.logger = logger

        # The osdpl object is used only to send events. Should not be
        # changed. For any source of data mspec should be used.
        self.osdpl = kube.get_osdpl()
        self.openstack_version = mspec["openstack_version"]

        self.helm_manager = helm.HelmManager(namespace=self.namespace)
        self.osdplst = osdplst
        self.child_view = child_view

    def _get_admin_creds(self) -> secrets.OpenStackAdminCredentials:
        admin_secret = secrets.OpenStackAdminSecret(self.namespace)
        return admin_secret.get()

    def _get_guest_creds(self) -> secrets.RabbitmqGuestCredentials:
        guest_secret = secrets.RabbitmqGuestSecret(self.namespace)
        guest_secret.ensure()
        return guest_secret.get()

    def is_service_enabled(self, service):
        return service in self.mspec["features"]["services"]

    @property
    def resource_name(self):
        return f"openstack-{self.service}"

    @property
    def resource_def(self):
        """Minimal representation of the resource"""

        res = {
            "apiVersion": f"{self.group}/{self.version}",
            "kind": self.kind,
            "metadata": {
                "name": self.resource_name,
            },
        }
        return res

    @property
    def enabled(self):
        return self.service in self.mspec["features"]["services"]

    @property
    def health_groups(self):
        return []

    @property
    def child_objects(self):
        res = []
        child_objects = layers.render_template(
            f"child_objects/{self.service}.yaml", spec=self.mspec
        )
        for chart_name, kinds in child_objects.items():
            for kind, objects in kinds.items():
                for obj_name, meta in objects.items():
                    obj_type = meta.get("type", "static")
                    if obj_type != "static":
                        continue
                    m_ext = {}
                    for field in ["images", "hash_fields", "manifest"]:
                        if field in meta:
                            m_ext[field] = meta[field]
                    m_ext["chart"] = chart_name
                    m_ext_obj = kube.HelmBundleExt(**m_ext)
                    child_obj = kube.dummy(
                        kube.__getattribute__(kind),
                        obj_name,
                        self.namespace,
                    )
                    child_obj.helmbundle_ext = m_ext_obj
                    child_obj.service = self
                    res.append(child_obj)
        return res

    async def set_release_values(self, chart, values):
        await self.helm_manager.set_release_values(
            f"openstack-{chart}", values, chart
        )
        LOG.info(f"Update {self.service} with {values}")

    def get_child_objects_dynamic(self, kind, abstract_name):
        res = []
        child_objects = layers.render_template(
            f"child_objects/{self.service}.yaml", spec=self.mspec
        )
        for chart_name, kinds in child_objects.items():
            for kinds, objects in kinds.items():
                for obj_name, meta in objects.items():
                    obj_type = meta.get("type", "static")
                    if obj_type != "dynamic":
                        continue
                    if obj_name != abstract_name:
                        continue
                    m_ext = {}
                    for field in ["images", "hash_fields", "manifest"]:
                        if field in meta:
                            m_ext[field] = meta[field]
                    m_ext["chart"] = chart_name
                    m_ext_obj = kube.HelmBundleExt(**m_ext)
                    selector = {
                        f"{k}__in": [v] for k, v in meta["pod_labels"].items()
                    }
                    for dynamic_object in kube.resource_list(
                        kube.__getattribute__(kind),
                        selector=selector,
                        namespace=self.namespace,
                    ):
                        child_obj = kube.dummy(
                            kube.__getattribute__(kind),
                            dynamic_object.name,
                            dynamic_object.namespace,
                        )
                        child_obj.helmbundle_ext = m_ext_obj
                        child_obj.service = self
                        res.append(child_obj)
        return res

    def get_child_object(self, kind, name):
        return [
            child
            for child in self.child_objects
            if child.kind == kind and child.name == name
        ][0]

    def get_child_object_current_hash(self, child_object, values):
        """Get currently defined child object hash stored
        in HelmBundle release annotations.

        :param child_object: Child object
        :param values: Values of helm release
        :returns: String with hash or None
        """
        child_obj_metadata = (
            values.get(f"{self.group}/{self.version}", {})
            .get("rockoon", {})
            .get("child-objects", {})
        )
        return (
            child_obj_metadata.get(child_object.helmbundle_ext.chart, {})
            .get(child_object.kind, {})
            .get(child_object.name, {})
            .get("hash", None)
        )

    def generate_child_object_hash(self, child_object, values):
        """Generate stable hash of child object

        The has takes into account hash_fileds and create stable hash
        by taking values from release.

        :param child_object: The child object
        :param: values: The values for release object data.
        :return: string with hash
        """

        if not child_object.helmbundle_ext.hash_fields:
            return None

        hasher = hashlib.sha256()
        resource_hash_data = {}
        for field in child_object.helmbundle_ext.hash_fields:
            resource_hash_data[field] = [
                match.value for match in parse(field).find(values)
            ]
        hasher.update(json.dumps(resource_hash_data, sort_keys=True).encode())
        return hasher.hexdigest()

    def generate_child_object_hashes(self, data):
        """Generate stable hash of child objects

        The has takes into account hash_fileds and create stable hash
        by taking values from release. Return json data with hashes.

        :param: data: The whole helmbundle object data.
        :return: json data with hash. Example
            {"<obj-kind Job|Deployment>": {
                "<job-name>": {
                    "hash": "<sha256hash>"
                    }
                }
            }
        """
        res = {}
        release_mapping = {}
        for release in data["spec"]["releases"]:
            chart_name = release["chart"]

            release_mapping[chart_name] = {
                "new_values": release["values"],
            }

        for child_object in self.child_objects:
            child_object_hash = self.generate_child_object_hash(
                child_object,
                release_mapping.get(child_object.helmbundle_ext.chart, {}).get(
                    "new_values", {}
                ),
            )
            child_hash = {
                child_object.helmbundle_ext.chart: {
                    child_object.kind: {
                        child_object.name: {"hash": child_object_hash}
                    }
                }
            }
            layers.merger.merge(res, child_hash)
        return res

    async def is_child_object_hash_changed(
        self, child_object, old_values, new_values
    ):
        """Check if object hash was changed

        :param child_object: Child object
        :param data: The whole helmbundle object data
        :returns: True when current hash not equal to hash in annotation
        """
        current_hash = self.get_child_object_current_hash(
            child_object, old_values
        )
        new_hash = self.generate_child_object_hash(child_object, new_values)
        return new_hash != current_hash

    async def cleanup_immutable_resources(self, new_obj, force=False):
        """
        Remove immmutable resources for helmbundle object when:
            1. The hash for release values fields used in child object
               is changed.
            2. The image of immutable object is changed
            3. The chart version for helmbundle is changed
            4. The force flag is set to True
        :param new_obj: the new helmbundle object representation
        :param rendered_spec: the current representation of helmbundle
        :param force: the flag to force remove all immutable objects that we know about.
        """
        to_cleanup = set()

        release_mapping = {}
        installed_releases = [
            release["name"] for release in await self.helm_manager.list()
        ]
        for release in new_obj["spec"]["releases"]:
            if not release["name"] in installed_releases:
                break
            chart_name = release["chart"]
            old_values = await self.helm_manager.get_release_values(
                release["name"]
            )
            release_mapping[chart_name] = {
                "new_values": release["values"],
                "old_values": old_values,
            }

        async def _is_immutable_changed(image, chart_name):
            old_values = release_mapping.get(chart_name, {}).get(
                "old_values", {}
            )
            new_values = release_mapping.get(chart_name, {}).get(
                "new_values", {}
            )
            # For case when inf ochild object doesn't exist in values.
            if not old_values and not new_values:
                return False

            old_image = old_values["images"]["tags"].get(image)
            new_image = new_values["images"]["tags"][image]

            # When image name is changed it will not present in helmbundle object
            # on deployed environmet. At the same time in current version of code
            # we will use new name of image.
            if old_image is None or old_image != new_image:
                return True

        for resource in self.child_objects:
            if not resource.exists():
                continue
            # NOTE(vsaienko): Do not try to remove object if hash_fields are empty
            # but still allow to remove the object if it is immutable, we need to
            # still check for image changes
            if (
                not resource.immutable
                and not resource.helmbundle_ext.hash_fields
            ):
                continue

            # NOTE(vsaienko): even the object is not immutable, it may have immutable fields.
            chart_name = resource.helmbundle_ext.chart
            old_values = release_mapping.get(chart_name, {}).get(
                "old_values", {}
            )
            new_values = release_mapping.get(chart_name, {}).get(
                "new_values", {}
            )
            # For case when inf ochild object doesn't exist in values.
            if not old_values and not new_values:
                continue
            if await self.is_child_object_hash_changed(
                resource, old_values, new_values
            ):
                to_cleanup.add(resource)
            if resource.immutable:
                for image in resource.helmbundle_ext.images:
                    if force or await _is_immutable_changed(
                        image, resource.helmbundle_ext.chart
                    ):
                        to_cleanup.add(resource)
                        # Break on first image match.
                        break
        LOG.info(f"Removing the following jobs: {to_cleanup}")
        tasks = set()
        for child_object in to_cleanup:
            tasks.add(child_object.purge())
        await asyncio.gather(*tasks)

    async def delete(self, *, body, meta, spec, logger, **kwargs):
        LOG.info(f"Deleting config for {self.service}")
        self.set_children_status("Deleting")
        # TODO(e0ne): remove credentials of the deleted services
        await self.helm_manager.delete_bundle(self.available_releases)
        msg = f"Deleted helm release {self.resource_name} for service {self.service}"
        LOG.info(msg)

        # remove child reference from status
        self.set_children_status(None)
        kopf.info(
            body,
            reason="Delete",
            message=msg,
        )

    def set_children_status(self, status):
        apply_statuses = ("Applying", "Upgrading")
        applied_status = (True,)
        delete_status = ("Deleting",)
        deleted_status = (None,)

        if status in apply_statuses:
            self.osdplst.set_service_status(self.service, APPLYING, self.mspec)
        elif status in applied_status:
            self.osdplst.set_service_status(self.service, APPLIED, self.mspec)
        elif status in delete_status:
            self.osdplst.set_service_status(self.service, DELETING, self.mspec)
        elif status in deleted_status:
            self.osdplst.remove_service_status(self.service)

    async def apply(self, event, **kwargs):
        self.set_children_status("Applying")
        LOG.info(f"Applying config for {self.service}")
        data = self.render()
        if kwargs.get("helmobj_overrides", {}):
            self._merge_helm_override(data, kwargs["helmobj_overrides"])

        for release in data["spec"]["releases"]:
            await self.cleanup_immutable_resources(data)
        try:
            await self.helm_manager.install_bundle(data)
        except:
            raise

        await self.helm_manager.delete_not_active_releases(
            data, self.available_releases
        )

        LOG.info(f"Config applied for {self.service}")
        kopf.info(
            self.osdpl.obj,
            reason=event.capitalize(),
            message=f"{event}d for {self.service}",
        )
        self.set_children_status(True)

    def _merge_helm_override(self, data, overrides):
        for release in data["spec"]["releases"]:
            name = release["name"]
            if name in overrides:
                LOG.info(
                    f"Setting values {overrides[name]} for release {name}"
                )
                layers.merger.merge(release["values"], overrides[name])

    async def wait_service_healthy(self):
        for health_group in self.health_groups:
            LOG.info(f"Checking {health_group} health.")
            readiness_timeouts = (
                self.mspec.get("timeouts", {})
                .get("application_readiness", {})
                .get(health_group, {})
            )
            delay = readiness_timeouts.get(
                "delay", CONF.getint("osctl", "wait_application_ready_delay")
            )
            timeout = readiness_timeouts.get(
                "timeout",
                CONF.getint("osctl", "wait_application_ready_timeout"),
            )
            await health.wait_application_ready(
                health_group, self.osdplst, delay=delay, timeout=timeout
            )

    async def _upgrade(self, event, **kwargs):
        pass

    async def upgrade(self, event, **kwargs):
        self.set_children_status("Upgrading")
        try:
            await self.wait_service_healthy()
            LOG.info(f"Upgrading {self.service} started.")
            await self._upgrade(event, **kwargs)

            await self.apply(event, **kwargs)
            # TODO(vsaienko): implement logic that will check that changes made in helmbundle
            # object were handled by tiller/helmcontroller
            # can be done only once https://mirantis.jira.com/browse/PRODX-2283 is implemented.
            await asyncio.sleep(
                CONF.getint("helmbundle", "manifest_apply_delay")
            )

            await self.wait_service_healthy()
        except Exception as e:
            # NOTE(vsaienko): always raise temporary error here, to ensure we retry upgrade from
            # failed service only. The whole upgrade restart might be done by restarting openstack
            # controller.
            LOG.exception(f"Got {e} when upgrading service {self.service}.")
            raise kopf.TemporaryError(f"Retrying to upgrade {self.service}")
        self.set_children_status(True)
        LOG.info(f"Upgrading {self.service} done")

    def template_args(self):
        template_args = {}
        if self.service_secret is not None:
            self.service_secret.ensure()
            credentials = self.service_secret.get_all()
            template_args["credentials"] = credentials

        if settings.OSCTL_PROXY_DATA["enabled"]:
            proxy_secret = secrets.ProxySecret()
            proxy_secret.wait()
            domain_names = [
                self.mspec["internal_domain_name"],
                "$(NODE_IP)",
            ]
            proxy_vars, proxy_settings = proxy_secret.get_proxy_vars(
                no_proxy=domain_names
            )

            template_args["proxy_vars"] = proxy_vars
            template_args["proxy_settings"] = proxy_settings
            LOG.debug(
                f"Set proxy variables for {self.service}: {template_args['proxy_vars']}"
            )
        template_args["network_policies"] = self.child_view.network_policies
        template_args["service_childs"] = self.child_view.childs
        return template_args

    @layers.kopf_exception
    def render(self, openstack_version=""):
        if openstack_version:
            self.mspec["openstack_version"] = openstack_version
        template_args = self.template_args()
        data = layers.merge_all_layers(
            self.service,
            self.mspec,
            self.logger,
            **template_args,
        )

        data.update(self.resource_def)
        kopf.adopt(data, self.osdpl.obj)

        # Add internal data to helm release

        fingerprint = layers.spec_hash(self.mspec)
        child_hashes = self.generate_child_object_hashes(data)
        internal_data = {
            f"{self.group}/{self.version}": {
                "rockoon": {
                    "version": version.release_string,
                    "fingerprint": fingerprint,
                    "child-objects": child_hashes,
                    "ownerReferences": data["metadata"]["ownerReferences"],
                    "helmbundle": {"name": self.resource_name},
                }
            }
        }

        for release in data["spec"]["releases"]:
            layers.merger.merge(release["values"], internal_data)
        return data

    def get_chart_value_or_none(
        self, chart, path, openstack_version=None, default=None
    ):
        data = self.render(openstack_version)
        value = None
        for release in data["spec"]["releases"]:
            if release["chart"] == chart:
                value = release["values"]
                try:
                    for path_link in path:
                        value = value[path_link]
                except KeyError:
                    return default
        return value

    def get_image(self, name, chart, openstack_version=None):
        return self.get_chart_value_or_none(
            chart,
            ["images", "tags", name],
            openstack_version=openstack_version,
        )


class MaintenanceApiMixin:
    @abstractmethod
    async def remove_node_from_scheduling(self, node):
        pass

    @abstractmethod
    async def prepare_node_for_reboot(self, node):
        pass

    @abstractmethod
    async def prepare_node_after_reboot(self, node):
        pass

    @abstractmethod
    async def add_node_to_scheduling(self, node):
        pass

    async def process_nmr(self, node, nmr):
        await self.remove_node_from_scheduling(node)
        if nmr.is_reboot_possible():
            LOG.info(f"The reboot is possible, migrating workloads")
            await self.prepare_node_for_reboot(node)

    async def delete_nmr(self, node, nmr):
        await self.prepare_node_after_reboot(node)
        await self.add_node_to_scheduling(node)

    async def can_handle_nmr(self, node, locks):
        """Check if it is possible to handle nmr for node

        :param node: the node we want to handle nmr for
        :param locks: currently active locks

        :returns True: when can handle nmr of node.
        :returns False: When not possible to handle nmr for node.
        """
        return True

    async def process_ndr(self, node, nwl):
        """Process NodeDeletionRequest.

        At this point kubernetes node is present, and all pods are
        running. It is good time to evacuate all workloads from the
        node.

        :param node: the node object
        :param nwl: the nodeworkloadlock object

        :raises kopf.TemporaryError on errors.

        """
        pass

    async def cleanup_metadata(self, nwl):
        """Cleanup metadata tied with specific node.

        At this point no pods are running on the node so here
        we can proceed with metadata cleanup.

        :param nwl: the nodeWorkloadLock object

        :raises kopf.TemporaryError on errors.
        """
        pass

    async def cleanup_persistent_data(self, nwl):
        """Cleanup persistent data tied with specific node.

        At this point no pods should be running on the node, and
        node object may not be present in kubernetes.

        :param nwl: the nodeWorkloadLock object

        :raises kopf.TemporaryError on errors.
        """
        pass

    async def is_node_locked(self, node_name):
        """Check if node is hard locked by application.

        Ensure that clustered application will not loose quorum if
        node is removed. Is a safer to allow persistant metadata removal.

        :param node_name: The name of the node we want to check.

        :returns True: When node is locked and we will loose quorum.
        :retruns False: When we are okay to loose data on this node.

        :raises kopf.TemporaryError on errors.
        """
        return False


class OpenStackService(Service):
    openstack_chart = None
    _secret_class = secrets.OpenStackServiceSecret

    @property
    def health_groups(self):
        return [self.openstack_chart]

    @property
    def is_ceph_enabled(self):
        return False

    def _get_keystone_creds(self):
        result = {}
        for svc, accs in self.required_accounts.items():
            secret_class = Service.registry[svc](
                self.mspec, self.logger, self.osdplst, self.child_view
            ).service_secret
            if secret_class:
                secret_class.wait()
                for k, v in secret_class.get().identity.items():
                    if k in accs:
                        result[k] = v
        return result

    def template_args(self):
        template_args = super().template_args()

        admin_creds = self._get_admin_creds()
        guest_creds = self._get_guest_creds()
        keystone_creds = self._get_keystone_creds()

        template_args.update(
            {
                "admin_creds": admin_creds,
                "guest_creds": guest_creds,
                "keystone_creds": keystone_creds,
                "is_ceph_enabled": self.is_ceph_enabled,
            }
        )
        return template_args


class OpenStackServiceWithCeph(OpenStackService):
    @property
    def is_ceph_enabled(self):
        return True

    def ensure_ceph_secrets(self):
        self.create_ceph_secrets()

    def create_ceph_secrets(self):
        LOG.info("Waiting for ceph resources.")
        kube.wait_for_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE,
            ceph_api.OPENSTACK_KEYS_SECRET,
        )
        oscp = ceph_api.get_os_ceph_params(secrets.get_secret_data)
        # TODO(vsaienko): the subset of secrets might be changed after
        # deployment. For example additional service is deployed,
        # we need to handle this.
        self.save_ceph_secrets(oscp)
        LOG.info("Ceph resources were created successfully.")

    def save_ceph_secrets(self, params: ceph_api.OSCephParams):
        kube_api = kube.kube_client()
        for service in params.services:
            name = ceph_api.get_os_user_keyring_name(service.user)
            secret = {
                "metadata": {"name": name, "namespace": self.namespace},
                "data": {
                    "key": base64.b64encode(service.key.encode()).decode()
                },
            }
            try:
                pykube.Secret(kube_api, secret).create()
            except Exception:
                # TODO check for resource exists exception.
                pass

    @staticmethod
    def get_ceph_role_pools(oscp: ceph_api.OSServiceCreds):
        ret = {}
        service_user = oscp.user.name
        for pool in oscp.pools:
            if pool.role.name in ceph_api.CEPH_POOL_ROLE_SERVICES_MAP.get(
                service_user
            ):
                ret.update(
                    {pool.name: {"name": pool.name, "role": pool.role.name}}
                )

        return ret

    def ceph_config(self):
        ceph_config = {}
        oscp = ceph_api.get_os_ceph_params(secrets.get_secret_data)
        for oscp_service in oscp.services:
            srv_username = oscp_service.user.name
            ceph_config[srv_username] = {
                "username": srv_username,
                "keyring": oscp_service.key,
                "secrets": ceph_api.get_os_user_keyring_name(
                    oscp_service.user
                ),
                "pools": self.get_ceph_role_pools(oscp_service),
            }
        ceph_config["mon_host"] = [
            f"{ip}:{port}" for ip, port in oscp.mon_endpoints
        ]
        return {"ceph": ceph_config}

    async def apply(self, event, **kwargs):
        # ensure child ref exists in the status
        if self.is_ceph_enabled:
            self.ensure_ceph_secrets()
        await super().apply(event, **kwargs)

    def template_args(self):
        template_args = super().template_args()
        if self.is_ceph_enabled:
            template_args.update(self.ceph_config())
        return template_args
