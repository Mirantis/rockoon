import logging
import requests
import unittest

import openstack
from parameterized import parameterized

from rockoon.tests.functional import base, config
from rockoon import kube

LOG = logging.getLogger(__name__)
CONF = config.Config()


def get_enabled_providers():
    osdpl = kube.get_osdpl()
    enabled_providers = []
    for provider_name, provider in (
        osdpl.obj["spec"]["features"]
        .get("keystone", {})
        .get("federation", {})
        .get("openid", {})
        .get("providers", {})
        .items()
    ):
        if provider.get("enabled", True):
            enabled_providers.append(provider_name)
    return enabled_providers


class TestKeystoneFederation(base.BaseFunctionalTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if (
            not cls.osdpl.obj["spec"]["features"]
            .get("keystone", {})
            .get("federation", {})
            .get("openid", {})
            .get("enabled", False)
        ):
            raise unittest.SkipTest("Keystone federation is not enabled.")

    def setUp(self):
        super().setUp()
        self.providers = self.osdpl_spec["features"]["keystone"]["federation"][
            "openid"
        ]["providers"]

    def get_auth_data(self, provider_name):
        auth = CONF.FEDERATION_USERS
        if provider_name not in auth.keys():
            raise unittest.SkipTest(
                f"No user credentials for provider '{provider_name}'."
            )

        provider = self.providers[provider_name]
        discovery_endpoint = (
            f"{provider['issuer']}/.well-known/openid-configuration"
        )
        return {
            "os_auth_type": "v3oidcpassword",
            "os_identity_provider": provider_name,
            "os_protocol": "mapped",
            "os_openid_scope": "openid",
            "os_password": auth[provider_name]["password"],
            "os_project_domain_name": "Default",
            "os_project_name": "admin",
            "os_discovery_endpoint": discovery_endpoint,
            "os_auth_url": "http://keystone-api.openstack.svc.cluster.local:5000/v3",
            "os_insecure": True,
            "os_client_secret": provider["metadata"]["client"].get(
                "client_secret", "NotNeeded"
            ),
            "os_client_id": provider["metadata"]["client"]["client_id"],
            "os_username": auth[provider_name]["username"],
            "os_interface": "internal",
            "os_endpoint_type": "internal",
            "api_timeout": 60,
        }

    @parameterized.expand(get_enabled_providers(), skip_on_empty=True)
    def test_keystone_federation(self, provider_name):
        auth_data = self.get_auth_data(provider_name)
        envs = (
            f"OS_CLIENT_SECRET={auth_data['os_client_secret']} "
            f"OS_PROJECT_DOMAIN_ID=default "
            f"OS_INTERFACE=public "
            f"OS_USERNAME={auth_data['os_username']} "
            f"OS_PASSWORD={auth_data['os_password']} "
            f"OS_CACERT=/etc/ssl/certs/openstack-ca-bundle.pem "
            f"OS_AUTH_URL=http://keystone-api.openstack.svc.cluster.local:5000/v3 "
            f"OS_CLIENT_ID={auth_data['os_client_id']} "
            f"OS_PROTOCOL=mapped "
            f"OS_IDENTITY_PROVIDER={auth_data['os_identity_provider']} "
            f"OS_DISCOVERY_ENDPOINT={auth_data['os_discovery_endpoint']} "
            f"OS_AUTH_TYPE=v3oidcpassword "
            f"OS_PROJECT_NAME=admin "
            f"OS_CLOUD="
        )
        error_msg = "===ERROR==="
        LOG.info(
            "\n",
            self.keystone_client_pod.exec(
                ["/bin/bash", "-c", f"{envs} env|grep OS_"]
            ),
        )
        server_list = self.keystone_client_pod.exec(
            [
                "/bin/bash",
                "-c",
                f"{envs} "
                f"openstack -vvv --insecure server list "
                f"|| echo '{error_msg}'",
            ]
        )
        if error_msg in server_list["stdout"]:
            raise Exception(f"\n{server_list}")

    @parameterized.expand(get_enabled_providers(), skip_on_empty=True)
    def test_keystone_federation_sdk(self, provider_name):
        auth_data = self.get_auth_data(provider_name)
        fed = openstack.connect(load_yaml_config=False, **auth_data)
        fed.authorize()
        assert (
            len(list(fed.network.networks())) > 0
        ), "List of networks is empty"

        assert (
            auth_data["os_username"]
            == fed.identity.get_user(fed.current_user_id).name
        ), "User name doesn't match"

        assert (
            auth_data["os_project_name"]
            == fed.identity.get_project(fed.current_project_id).name
        ), "Project name doesn't match"

    @parameterized.expand(get_enabled_providers(), skip_on_empty=True)
    def test_keystone_federation_req(self, provider_name):
        auth_data = self.get_auth_data(provider_name)
        verify = None

        if auth_data.get("os_cacert"):
            verify = auth_data["os_cacert"]
        elif auth_data.get("os_insecure") is True:
            verify = False

        timeout = auth_data.get("api_timeout", 60)

        discovery_resp = requests.get(
            auth_data["os_discovery_endpoint"],
            verify=verify,
            timeout=timeout,
        )

        token_endpoint = discovery_resp.json()["token_endpoint"]
        access_req_data = (
            "username={os_username}&password={os_password}&scope={os_openid_scope}&grant_type"
            "=password"
        ).format(**auth_data)

        access_resp = requests.post(
            token_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=access_req_data,
            auth=(
                auth_data["os_client_id"],
                auth_data["os_client_secret"],
            ),
            verify=verify,
            timeout=timeout,
        )

        access_token = access_resp.json()["access_token"]

        unscoped_token_resp = requests.post(
            "{os_auth_url}/OS-FEDERATION/identity_providers/{os_identity_provider}/protocols/{os_protocol}/auth".format(
                **auth_data
            ),
            headers={"Authorization": f"Bearer {access_token}"},
            verify=verify,
            timeout=timeout,
        )

        unscoped_token = unscoped_token_resp.headers.get("x-subject-token")

        scoped_auth_req = {
            "auth": {
                "identity": {
                    "methods": ["token"],
                    "token": {"id": unscoped_token},
                },
                "scope": {
                    "project": {
                        "domain": {
                            "name": auth_data["os_project_domain_name"]
                        },
                        "name": auth_data["os_project_name"],
                    }
                },
            }
        }

        scoped_token_resp = requests.post(
            "{os_auth_url}/auth/tokens".format(**auth_data),
            headers={"Content-Type": "application/json"},
            json=scoped_auth_req,
            verify=verify,
            timeout=timeout,
        )

        # more info on user, its roles and groups is in the JSON body of the response
        scoped_token = scoped_token_resp.headers.get("x-subject-token")

        catalog = scoped_token_resp.json()["token"]["catalog"]
        interface = auth_data.get("os_interface", "public")

        network_service = [s for s in catalog if s["type"] == "network"]
        if network_service:
            network_service = network_service[0]
        else:
            raise Exception("Could not find network service in catalog")

        network_api = [
            e["url"]
            for e in network_service["endpoints"]
            if e["interface"] == interface
        ]

        if network_api:
            network_api = network_api[0]
            if not network_api.rstrip("/").endswith("/v2.0"):
                network_api = network_api.rstrip("/") + "/v2.0"
        else:
            raise Exception(
                "Could not find required endpoint for network service"
            )

        networks_resp = requests.get(
            f"{network_api}/networks",
            headers={"X-Auth-Token": scoped_token},
            verify=verify,
            timeout=timeout,
        )

        assert (
            networks_resp.status_code == requests.codes.ok
        ), f"GET /networks response is not OK {networks_resp.status_code}"
        assert (
            len(networks_resp.json()["networks"]) > 0
        ), f"GET /networks response was {networks_resp.text}"
