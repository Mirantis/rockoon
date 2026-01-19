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

import copy
import logging
from unittest import mock

import kopf
import openstack
from openstack.utils import Munch
import pytest

from rockoon import constants
from rockoon import kube
from rockoon import secrets
from rockoon import services
from rockoon import settings
from rockoon import maintenance

NODE_OBJ = {
    "apiVersion": "v1",
    "kind": "Node",
    "metadata": {
        "name": "host1",
        "uid": "42",
    },
}

VOLUME_SERVICE_OBJ = {
    "binary": "cinder-volume",
    "host": "host1@lvm",
    "zone": "nova",
    "status": "enabled",
    "state": "up",
    "updated_at": "2023-05-31T07:50:33.000000",
    "disabled_reason": "test",
    "replication_status": "disabled",
    "active_backend_id": None,
    "frozen": False,
}


def _get_node(host="host1", role="compute"):
    node_obj = copy.deepcopy(NODE_OBJ)
    node_obj["metadata"]["name"] = host
    if role == "compute":
        node_obj["metadata"]["labels"] = {"openstack-compute-node": "enabled"}
    if role == "control":
        node_obj["metadata"]["labels"] = {"openstack-control-plane": "enabled"}
    return node_obj


def _get_nwl_obj(controller, host):
    return {
        "apiVersion": "v1",
        "kind": "NodeWorkloadLock",
        "metadata": {
            "name": f"{controller}-{host}",
        },
        "spec": {
            "controllerName": controller,
            "nodeName": host,
            "nodeDeletionRequestSupported": True,
        },
    }


@pytest.fixture
def kube_find(mocker):
    mock_get_obj = mocker.patch(
        "rockoon.kube.find",
        mock.Mock(),
    )
    yield mock_get_obj
    mocker.stopall()


@pytest.fixture
def mock_sts(mocker):
    sts = mocker.patch("rockoon.kube.StatefulSet")
    sts.return_value = mock.MagicMock()
    yield sts
    mocker.stopall()


def get_clustered_service_classes():
    return [services.Coordination, services.MariaDB]


@mock.patch("rockoon.secrets.generate_name")
@mock.patch("rockoon.secrets.generate_password")
@mock.patch.object(secrets.OpenStackAdminSecret, "k8s_get_data")
@mock.patch.object(secrets, "get_secret_priority")
def test_get_admin_creds(
    mock_priority,
    mock_data,
    mock_password,
    mock_name,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
):
    osdplstmock = mock.MagicMock()
    service = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    mock_kube_get_osdpl.assert_called_once()

    mock_name.return_value = "admin1234"
    mock_password.return_value = "password"

    mock_data.return_value = {
        "database": "eyJ1c2VybmFtZSI6ICJyb290IiwgInBhc3N3b3JkIjogInBhc3N3b3JkIn0=",
        "identity": "eyJ1c2VybmFtZSI6ICJhZG1pbjEyMzQiLCJwYXNzd29yZCI6ICJwYXNzd29yZCJ9Cg==",
        "messaging": "eyJ1c2VybmFtZSI6ICJyYWJiaXRtcSIsICJwYXNzd29yZCI6ICJwYXNzd29yZCJ9",
    }
    mock_priority.return_value = 0

    expected_secret = secrets.OpenStackAdminSecret("namespace")
    expected_creds = expected_secret.create()

    admin_creds = service._get_admin_creds()
    assert expected_creds.database.username == admin_creds.database.username
    assert expected_creds.database.password == admin_creds.database.password
    assert expected_creds.identity.username == admin_creds.identity.username
    assert expected_creds.identity.password == admin_creds.identity.password
    assert expected_creds.messaging.username == admin_creds.messaging.username
    assert expected_creds.messaging.password == admin_creds.messaging.password


@mock.patch.object(services.Keystone, "template_args")
def test_service_keystone_render(
    mock_template_args,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    mock_kube_artifacts_configmap,
):
    osdplstmock = mock.MagicMock()
    creds = secrets.OSSytemCreds("test", "test")
    admin_creds = secrets.OpenStackAdminCredentials(creds, creds, creds)
    guest_creds = secrets.RabbitmqGuestCredentials(
        password="secret",
    )
    creds_dict = {"user": creds, "admin": creds}
    credentials = secrets.OpenStackCredentials(
        database=creds_dict,
        messaging=creds_dict,
        notifications=creds_dict,
        memcached="secret",
    )
    keystone_creds = {"test": secrets.OSSytemCreds("test", "test")}

    mock_template_args.return_value = {
        "credentials": [credentials],
        "admin_creds": admin_creds,
        "guest_creds": guest_creds,
        "keystone_creds": keystone_creds,
        "federation": {"enabled": False},
    }
    openstackdeployment_mspec["services"]["identity"]["keystone"]["values"] = {
        "pod": {"replicas": {"api": 333}}
    }
    openstackdeployment_old = copy.deepcopy(openstackdeployment_mspec)
    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    identity_helmbundle = service.render()
    # check no modification in-place for openstackdeployment
    assert openstackdeployment_old == openstackdeployment_mspec
    assert identity_helmbundle["metadata"]["name"] == "openstack-identity"
    # check helmbundle has data from base.yaml
    assert (
        identity_helmbundle["spec"]["releases"][0]["values"]["pod"][
            "replicas"
        ]["api"]
        == 333
    )
    assert identity_helmbundle["spec"]["releases"][0]["values"]["images"][
        "tags"
    ]


def test_service_keystone_federation_redirect_uri(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    assert (
        service.federation_redirect_uri
        == "https://keystone.it.just.works/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/mapped/websso/"
    )


def test_service_keystone_get_federation_default_provider_mapping(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    default_mapping_expected = [
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

    assert (
        default_mapping_expected
        == service._get_federation_default_provider_mapping()
    )


def test_service_keystone_get_federation_provider_defaults(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    default_provider_expected = {
        "enabled": True,
        "issuer": "https://my.provider/issuer",
        "metadata": {
            "client": {"client_id": "os"},
            "conf": {
                "response_type": "id_token",
                "scope": "openid email profile",
                "ssl_validate_server": False,
            },
            "provider": {
                "value_from": {
                    "from_url": {
                        "url": "https://my.provider/issuer/.well-known/openid-configuration"
                    }
                }
            },
        },
        "oauth2": {"OAuth2TargetPass": "prefix=OIDC-"},
    }

    assert (
        default_provider_expected
        == service._get_federation_provider_defaults(
            "https://my.provider/issuer"
        )
    )


def test_service_keystone_get_federation_keycloak_provider(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    openstackdeployment_mspec["features"]["keystone"]["keycloak"].update(
        {
            "client": "os",
            "enabled": True,
            "oidcCASecret": "oidc-cert",
            "url": "https://keycloak.it.just.works",
        }
    )

    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    res = service._get_federation_keycloak_provider()
    expected = {
        "enabled": True,
        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
        "description": "External Authentication Service",
        "metadata": {
            "client": {"client_id": "os"},
            "conf": {
                "response_type": "id_token",
                "scope": "openid email profile",
                "ssl_validate_server": False,
                "oauth_verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
                "verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
            },
            "provider": {
                "value_from": {
                    "from_url": {
                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                    }
                }
            },
        },
        "oauth2": {
            "OAuth2TargetPass": "prefix=OIDC-",
            "OAuth2TokenVerify": "jwks_uri https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs jwks_uri.ssl_verify=false",
        },
    }
    assert res == expected


def test_service_keystone_get_federation_keycloak_provider_overrides(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    openstackdeployment_mspec["features"]["keystone"]["keycloak"].update(
        {
            "client": "os",
            "enabled": True,
            "oidcCASecret": "oidc-cert",
            "url": "https://keycloak.it.just.works",
            "oidc": {
                "OIDCSSLValidateServer": True,
                "OIDCScope": "openid email profile groups",
            },
        }
    )

    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    res = service._get_federation_keycloak_provider()
    expected = {
        "enabled": True,
        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
        "description": "External Authentication Service",
        "metadata": {
            "client": {"client_id": "os"},
            "conf": {
                "response_type": "id_token",
                "scope": "openid email profile groups",
                "ssl_validate_server": True,
                "oauth_verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
                "verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
            },
            "provider": {
                "value_from": {
                    "from_url": {
                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                    }
                }
            },
        },
        "oauth2": {
            "OAuth2TargetPass": "prefix=OIDC-",
            "OAuth2TokenVerify": "jwks_uri https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs jwks_uri.ssl_verify=false",
        },
    }
    assert res == expected


@mock.patch.object(secrets.KeycloakSecret, "get")
def test_service_keystone_get_federation_args(
    keycloak_mock, openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    keycloak_mock.return_value = secrets.KeycloackCreds("passphrase")
    openstackdeployment_mspec["features"]["keystone"]["keycloak"].update(
        {
            "client": "os",
            "enabled": True,
            "oidcCASecret": "oidc-cert",
            "url": "https://keycloak.it.just.works",
        }
    )

    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    res = service.get_federation_args()
    expected = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc_auth_type": "oauth20",
                "oidc": {
                    "OIDCClaimPrefix": "OIDC-",
                    "OIDCClaimDelimiter": ";",
                    "OIDCOAuthSSLValidateServer": "Off",
                    "OIDCSessionInactivityTimeout": "1800",
                    "OIDCRedirectURI": "https://keystone.it.just.works/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/mapped/websso/",
                    "OIDCClientID": "os",
                    "OIDCResponseType": "id_token",
                    "OIDCScope": "openid email profile",
                    "OIDCSSLValidateServer": "Off",
                    "OIDCProviderMetadataURL": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration",
                    "OIDCOAuthVerifyJwksUri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
                    "OIDCCryptoPassphrase": "passphrase",
                    "OIDCRedirectURLsAllowed": "^https://horizon.it.just.works/auth/logout$",
                },
                "providers": {
                    "keycloak": {
                        "enabled": True,
                        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
                        "description": "External Authentication Service",
                        "metadata": {
                            "client": {"client_id": "os"},
                            "conf": {
                                "response_type": "id_token",
                                "scope": "openid email profile",
                                "ssl_validate_server": False,
                                "oauth_verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
                                "verify_jwks_uri": "https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs",
                            },
                            "provider": {
                                "value_from": {
                                    "from_url": {
                                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                                    }
                                }
                            },
                        },
                        "oauth2": {
                            "OAuth2TargetPass": "prefix=OIDC-",
                            "OAuth2TokenVerify": "jwks_uri https://keycloak.it.just.works/auth/realms/iam/protocol/openid-connect/certs jwks_uri.ssl_verify=false",
                        },
                        "mapping": [
                            {
                                "local": [
                                    {"user": {"email": "{1}", "name": "{0}"}},
                                    {
                                        "domain": {"name": "Default"},
                                        "groups": "{2}",
                                    },
                                ],
                                "remote": [
                                    {"type": "OIDC-iam_username"},
                                    {"type": "OIDC-email"},
                                    {"type": "OIDC-iam_roles"},
                                ],
                            }
                        ],
                    }
                },
            }
        }
    }
    assert res == expected


@mock.patch.object(secrets.KeycloakSecret, "get")
def test_service_keystone_get_federation_args_keycloak_disabled_1provider(
    keycloak_mock,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    federation_provider,
):
    osdplstmock = mock.MagicMock()
    keycloak_mock.return_value = secrets.KeycloackCreds("passphrase")
    openstackdeployment_mspec["features"]["keystone"]["keycloak"].update(
        {
            "client": "os",
            "enabled": False,
            "oidcCASecret": "oidc-cert",
            "url": "https://keycloak.it.just.works",
        }
    )

    openstackdeployment_mspec["features"]["keystone"]["federation"] = {
        "openid": {
            "enabled": True,
            "oidc": {"OIDCFOO": "OIDCBAR"},
            "providers": {"provider1": federation_provider},
        }
    }

    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    res = service.get_federation_args()
    expected = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc_auth_type": "oauth2",
                "oidc": {
                    "OIDCClaimPrefix": "OIDC-",
                    "OIDCClaimDelimiter": ";",
                    "OIDCOAuthSSLValidateServer": "Off",
                    "OIDCSessionInactivityTimeout": "1800",
                    "OIDCRedirectURI": "https://keystone.it.just.works/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/mapped/websso/",
                    "OIDCFOO": "OIDCBAR",
                    "OIDCCryptoPassphrase": "passphrase",
                    "OIDCRedirectURLsAllowed": "^https://horizon.it.just.works/auth/logout$",
                },
                "providers": {
                    "provider1": {
                        "enabled": True,
                        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
                        "metadata": {
                            "client": {"client_id": "os"},
                            "conf": {
                                "response_type": "id_token",
                                "scope": "openid email profile",
                                "ssl_validate_server": False,
                            },
                            "provider": {
                                "value_from": {
                                    "from_url": {
                                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                                    }
                                }
                            },
                        },
                        "oauth2": {"OAuth2TargetPass": "prefix=OIDC-"},
                        "description": "Good provider",
                        "mapping": [
                            {
                                "local": [
                                    {"user": {"email": "{1}", "name": "{0}"}},
                                    {
                                        "domain": {"name": "Default"},
                                        "groups": "{2}",
                                    },
                                ],
                                "remote": [
                                    {"type": "OIDC-iam_username"},
                                    {"type": "OIDC-email"},
                                    {"type": "OIDC-iam_roles"},
                                ],
                            }
                        ],
                    }
                },
            }
        }
    }
    assert res == expected


@mock.patch.object(secrets.KeycloakSecret, "get")
def test_service_keystone_get_federation_args_2provider(
    keycloak_mock,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    federation_provider,
):
    osdplstmock = mock.MagicMock()
    keycloak_mock.return_value = secrets.KeycloackCreds("passphrase")
    provider2 = copy.deepcopy(federation_provider)
    provider2["issuer"] = "https://keycloak2.it.just.works/auth/realms/iam/"
    openstackdeployment_mspec["features"]["keystone"]["federation"] = {
        "openid": {
            "enabled": True,
            "oidc": {"OIDCFOO": "OIDCBAR"},
            "providers": {
                "provider1": federation_provider,
                "provider2": federation_provider,
            },
        }
    }

    service = services.Keystone(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    res = service.get_federation_args()
    expected = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc_auth_type": "oauth2",
                "oidc": {
                    "OIDCClaimPrefix": "OIDC-",
                    "OIDCClaimDelimiter": ";",
                    "OIDCOAuthSSLValidateServer": "Off",
                    "OIDCSessionInactivityTimeout": "1800",
                    "OIDCRedirectURI": "https://keystone.it.just.works/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/mapped/websso/",
                    "OIDCFOO": "OIDCBAR",
                    "OIDCCryptoPassphrase": "passphrase",
                    "OIDCRedirectURLsAllowed": "^https://horizon.it.just.works/auth/logout$",
                },
                "providers": {
                    "provider1": {
                        "enabled": True,
                        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
                        "metadata": {
                            "client": {"client_id": "os"},
                            "conf": {
                                "response_type": "id_token",
                                "scope": "openid email profile",
                                "ssl_validate_server": False,
                            },
                            "provider": {
                                "value_from": {
                                    "from_url": {
                                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                                    }
                                }
                            },
                        },
                        "oauth2": {"OAuth2TargetPass": "prefix=OIDC-"},
                        "description": "Good provider",
                        "mapping": [
                            {
                                "local": [
                                    {"user": {"email": "{1}", "name": "{0}"}},
                                    {
                                        "domain": {"name": "Default"},
                                        "groups": "{2}",
                                    },
                                ],
                                "remote": [
                                    {"type": "OIDC-iam_username"},
                                    {"type": "OIDC-email"},
                                    {"type": "OIDC-iam_roles"},
                                ],
                            }
                        ],
                    },
                    "provider2": {
                        "enabled": True,
                        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
                        "metadata": {
                            "client": {"client_id": "os"},
                            "conf": {
                                "response_type": "id_token",
                                "scope": "openid email profile",
                                "ssl_validate_server": False,
                            },
                            "provider": {
                                "value_from": {
                                    "from_url": {
                                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                                    }
                                }
                            },
                        },
                        "oauth2": {"OAuth2TargetPass": "prefix=OIDC-"},
                        "description": "Good provider",
                        "mapping": [
                            {
                                "local": [
                                    {"user": {"email": "{1}", "name": "{0}"}},
                                    {
                                        "domain": {"name": "Default"},
                                        "groups": "{2}",
                                    },
                                ],
                                "remote": [
                                    {"type": "OIDC-iam_username"},
                                    {"type": "OIDC-email"},
                                    {"type": "OIDC-iam_roles"},
                                ],
                            }
                        ],
                    },
                },
            }
        }
    }
    assert res == expected


@mock.patch.object(secrets.SignedCertificatePackSecret, "get")
@mock.patch.object(secrets.NeutronSecret, "get")
@mock.patch.object(services.base.OpenStackServiceWithCeph, "ceph_config")
@mock.patch.object(secrets.SSHSecret, "get")
@mock.patch.object(services.base.OpenStackService, "template_args")
def test_service_nova_with_ceph_render(
    mock_template_args,
    mock_ssh,
    mock_ceph_template_args,
    mock_neutron_secret,
    mock_vnc,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    mock_kube_artifacts_configmap,
):
    creds = secrets.OSSytemCreds("test", "test")
    admin_creds = secrets.OpenStackAdminCredentials(creds, creds, creds)
    guest_creds = secrets.RabbitmqGuestCredentials(
        password="secret",
    )
    creds_dict = {"user": creds, "admin": creds}
    credentials = secrets.OpenStackCredentials(
        database=creds_dict,
        messaging=creds_dict,
        notifications=creds_dict,
        memcached="secret",
    )
    keystone_creds = {"test": secrets.OSSytemCreds("test", "test")}

    mock_ssh.return_value = secrets.SshKey("public", "private")
    mock_vnc.return_value = secrets.SignedCertificatePack(
        "ca_cert",
        "ca_key",
        "server_cert",
        "server_key",
        "client_cert",
        "client_key",
    )
    mock_neutron_secret.return_value = secrets.NeutronCredentials(
        database=creds_dict,
        messaging=creds_dict,
        notifications=creds_dict,
        metadata_secret="metadata_secret",
        ipsec_secret_key="ipsec_secret",
    )

    osdplstmock = mock.MagicMock()
    mock_template_args.return_value = {
        "credentials": [credentials],
        "admin_creds": admin_creds,
        "guest_creds": guest_creds,
        "keystone_creds": keystone_creds,
    }

    mock_ceph_template_args.return_value = {
        "ceph": {
            "nova": {
                "username": "nova",
                "keyring": "key",
                "secrets": [],
                "pools": {},
            },
            "cinder": {
                "username": "cinder",
                "keyring": "key",
                "secrets": [],
                "pools": {},
            },
        }
    }

    openstackdeployment_old = copy.deepcopy(openstackdeployment_mspec)
    service = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    compute_helmbundle = service.render()
    # check no modification in-place for openstackdeployment
    assert openstackdeployment_old == openstackdeployment_mspec
    assert compute_helmbundle["metadata"]["name"] == "openstack-compute"
    # check helmbundle has data from base.yaml
    assert compute_helmbundle["spec"]["releases"][0]["values"]["images"][
        "tags"
    ]

    mock_ssh.assert_called()
    mock_vnc.assert_called()
    mock_ceph_template_args.assert_called_once()


# NOTE (e0ne): @mock.patch decorator doesn't work with coroutines


def test_service_apply(
    mocker,
    openstackdeployment_mspec,
    compute_helmbundle_all,
    mock_kube_get_osdpl,
    child_view,
):
    osdplstmock = mock.MagicMock()
    service = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )

    mock_render = mocker.patch.object(services.base.Service, "render")
    mock_render.return_value = compute_helmbundle_all

    mock_ceph_secrets = mocker.patch.object(
        services.Nova, "ensure_ceph_secrets"
    )
    mocker.patch("subprocess.check_call")
    mock_info = mocker.patch.object(kopf, "info")

    helm_run_cmd = mocker.patch(
        "rockoon.helm.HelmManager.run_cmd",
        return_value=mock.Mock(),
    )
    helm_run_cmd.return_value = ["fake_stdout", "fake_stderr"]

    helm_list = mocker.patch(
        "rockoon.helm.HelmManager.list",
        return_value=mock.Mock(),
    )
    helm_list.return_value = []
    mocker.patch.dict("os.environ", {"NODE_IP": "fake_ip"})

    service.apply("test_event")

    mock_render.assert_called_once()
    mock_ceph_secrets.assert_called_once()
    mock_info.assert_called_once()
    helm_run_cmd.assert_called()
    mock_kube_get_osdpl.assert_called_once()


def test_default_service_account_list(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    service = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    mock_kube_get_osdpl.assert_called_once()
    accounts = [constants.OS_SERVICES_MAP[service.service], "test"]
    assert accounts == service.service_accounts


def test_heat_service_account_list(
    openstackdeployment_mspec, mock_kube_get_osdpl, child_view
):
    osdplstmock = mock.MagicMock()
    service = services.Heat(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    accounts = ["heat_trustee", "heat_stack_user", "heat", "test"]
    mock_kube_get_osdpl.assert_called_once()
    assert accounts == service.service_accounts


@pytest.fixture
def openstack_client(mocker):
    oc_client = mocker.patch("rockoon.openstack_utils.OpenStackClientManager")
    oc_client.return_value = mock.MagicMock()
    yield oc_client
    mocker.stopall()


@pytest.fixture
def node_maintenance_config(mocker):
    nmc = mocker.patch("rockoon.maintenance.NodeMaintenanceConfig")
    nmc.return_value = mock.MagicMock()
    yield nmc
    mocker.stopall()


@pytest.fixture
def nwl(mocker):
    nwl = mocker.patch("rockoon.maintenance.NodeWorkloadLock")
    nwl.return_value = mock.MagicMock()
    yield nwl
    mocker.stopall()


def test_nova_prepare_node_after_reboot(
    mocker,
    openstack_client,
    kube_resource_list,
    kopf_adopt,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    kube_resource_list.return_value.get.return_value = mock.Mock(obj=None)
    compute_service = mock.Mock()
    compute_service.state = "up"
    openstack_client.return_value.compute_get_services.return_value = [
        compute_service
    ]
    osdplstmock = mock.Mock()
    with mock.patch.object(kube.Job, "create"):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_after_reboot(node)


def test_nova_prepare_node_after_reboot_not_compute(
    openstack_client,
    kube_resource_list,
    kopf_adopt,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node_obj = copy.deepcopy(NODE_OBJ)
    node_obj["metadata"]["labels"] = {}
    node = kube.Node(mock.Mock, node_obj)
    kube_resource_list.return_value.get.return_value = mock.Mock(obj=None)
    osdplstmock = mock.Mock()

    with mock.patch.object(kube.Job, "create"):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_after_reboot(node)
        kube_resource_list.return_value.get.assert_not_called()


@mock.patch("rockoon.utils.run_with_timeout")
def test_nova_prepare_node_after_reboot_timeout(
    run_with_timeout_mock,
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    run_with_timeout_mock.side_effect = TimeoutError("Timed out")
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_after_reboot(node)


@mock.patch("rockoon.utils.run_with_timeout")
def test_nova_prepare_node_after_reboot_openstacksdk_exception(
    run_with_timeout_mock,
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    openstack_client.side_effect = openstack.exceptions.SDKException("foo")
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_after_reboot(node)


def test_nova_add_node_to_scheduling(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    openstack_client.return_value.compute_get_services.return_value = [
        {
            "host": "host1",
            "disabled_reason": "OSDPL: Node is under maintenance",
        }
    ]
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).add_node_to_scheduling(node)
    openstack_client.return_value.compute_get_services.assert_called_once_with(
        host="host1"
    )
    openstack_client.return_value.compute_ensure_service_enabled.assert_called_once()


def test_nova_add_node_to_scheduling_not_compute(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node_obj = copy.deepcopy(_get_node())
    node_obj["metadata"]["labels"] = {}
    node = kube.Node(mock.Mock, node_obj)
    osdplstmock = mock.Mock()
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).add_node_to_scheduling(node)
    openstack_client.return_value.compute_get_services.assert_not_called()


def test_nova_add_node_to_scheduling_cannot_enable_service(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    openstack_client.side_effect = openstack.exceptions.SDKException("foo")
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).add_node_to_scheduling(node)


def test_nova_remove_node_from_scheduling(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).remove_node_from_scheduling(node)
    openstack_client.return_value.compute_get_services.assert_called_once()
    openstack_client.return_value.compute_ensure_service_disabled.assert_called_once()


def test_nova_remove_node_from_scheduling_not_compute(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node_obj = copy.deepcopy(_get_node())
    node_obj["metadata"]["labels"] = {}
    node = kube.Node(mock.Mock, node_obj)
    osdplstmock = mock.Mock()
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).remove_node_from_scheduling(node)
    openstack_client.return_value.compute_get_services.assert_not_called()


def test_nova_remove_node_from_scheduling_cannot_disable_service(
    openstack_client,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    openstack_client.return_value.compute_ensure_service_disabled.side_effect = openstack.exceptions.SDKException(
        "foo"
    )
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).remove_node_from_scheduling(node)


def test_nova_prepare_node_for_reboot(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()

    with mock.patch.object(
        services.Nova, "_migrate_servers", mock.Mock()
    ) as mock_migrate:
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_for_reboot(node)
        mock_migrate.assert_called_once()


def test_nova_prepare_node_for_reboot_not_compute(
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    node_obj = copy.deepcopy(_get_node())
    node_obj["metadata"]["labels"] = {}
    node = kube.Node(mock.Mock, node_obj)
    osdplstmock = mock.Mock()
    with mock.patch.object(
        services.Nova, "_migrate_servers", mock.Mock()
    ) as mock_migrate:
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).prepare_node_for_reboot(node)
        mock_migrate.assert_not_called()


def test_nova_prepare_node_for_reboot_sdk_exception(
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    openstack_client.side_effect = openstack.exceptions.SDKException("foo")
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    osdplstmock = mock.Mock()
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec,
            logging,
            osdplstmock,
            child_view,
        ).prepare_node_for_reboot(node)


def test_nova_migrate_servers_no_instances(
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    openstack_client.compute_get_all_servers.return_value = []

    node_maintenance_config.instance_migration_mode = "live"
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )._migrate_servers(openstack_client, "host1", node_maintenance_config, 1)
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()
    openstack_client.compute_get_servers_in_migrating_state.assert_not_called()


def test_nova_migrate_servers_skip(
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node_maintenance_config.instance_migration_mode = "skip"
    openstack_client.compute_get_server_maintenance_action.return_value = (
        "poweroff"
    )
    server = _get_server_obj()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    openstack_client.compute_get_all_servers.return_value = [server]
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )._migrate_servers(openstack_client, "host1", node_maintenance_config, 1)
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()
    openstack_client.compute_get_servers_in_migrating_state.assert_not_called()


def _get_server_obj(obj=None):
    if obj is None:
        obj = {}
    srv = openstack.compute.v2.server.Server()
    for k, v in obj.items():
        setattr(srv, k, v)
    return srv


def _get_service_obj(obj=None):
    if obj is None:
        obj = {}
    az = openstack.compute.v2.service.Service()
    for k, v in obj.items():
        setattr(az, k, v)
    return az


def _get_volume_obj(obj=None):
    if obj is None:
        obj = {}
    vol = openstack.block_storage.v3.volume.Volume()
    for k, v in obj.items():
        setattr(vol, k, v)
    return vol


def _get_volume_service_obj(obj=None):
    svc = copy.deepcopy(VOLUME_SERVICE_OBJ)
    if obj is not None:
        svc.update(obj)
    return svc


def compute_get_services_se(host, binary):
    svcs = {
        "host1": _get_service_obj(
            {"host": "host1", "location": Munch({"zone": "nova"})}
        ),
        "host2": _get_service_obj(
            {"host": "host2", "location": Munch({"zone": "nova"})}
        ),
        "host3": _get_service_obj(
            {"host": "host3", "location": Munch({"zone": "nova3"})}
        ),
    }

    return [svcs[host]]


def test_nova_migrate_servers_manual_one_server(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    openstack_client.compute_get_all_servers.return_value = [_get_server_obj()]

    node_maintenance_config.instance_migration_mode = "manual"
    openstack_client.compute_get_server_maintenance_action.return_value = (
        "notify"
    )
    nwl = mock.Mock()
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        )._migrate_servers(
            openstack_client, "host1", node_maintenance_config, nwl, 1
        )
    nwl.set_error_message.assert_called_once()
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()


def test_nova_migrate_servers_live_one_error_server(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
):
    osdplstmock = mock.Mock()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    srv = {"status": "ERROR"}
    openstack_client.compute_get_all_servers.return_value = [
        _get_server_obj(srv)
    ]

    node_maintenance_config.instance_migration_mode = "live"
    nwl = mock.Mock()
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        )._migrate_servers(
            openstack_client, "host1", node_maintenance_config, nwl, 1
        )
    nwl.set_error_message.assert_called_once()
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()


def test_nova_migrate_servers_live_ignore_powered_off_server(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
):
    osdplstmock = mock.Mock()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    openstack_client.compute_get_all_servers.return_value = [
        _get_server_obj({"power_state": 4}),
        _get_server_obj({"power_state": 6}),
        _get_server_obj({"power_state": 7}),
    ]

    node_maintenance_config.instance_migration_mode = "live"
    nwl = mock.Mock()
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )._migrate_servers(
        openstack_client, "host1", node_maintenance_config, nwl, 1
    )
    nwl.set_error_message.assert_not_called()
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()


def test_nova_migrate_servers_live_one_power_unknown(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
):
    osdplstmock = mock.Mock()
    openstack_client.compute_get_servers_valid_for_live_migration.return_value = (
        []
    )
    openstack_client.compute_get_all_servers.return_value = [
        _get_server_obj({"power_state": 4}),
        _get_server_obj({"power_state": 6}),
        _get_server_obj({"power_state": 7}),
        _get_server_obj({"power_state": 0}),
    ]

    node_maintenance_config.instance_migration_mode = "live"
    openstack_client.compute_get_server_maintenance_action.return_value = (
        "live_migrate"
    )
    nwl = mock.Mock()
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        )._migrate_servers(
            openstack_client, "host1", node_maintenance_config, nwl, 1
        )
    nwl.set_error_message.assert_called_once()
    openstack_client.compute_get_all_servers.assert_called_once()
    openstack_client.compute_get_servers_valid_for_live_migration.assert_called_once()


def test_nova_can_handle_nmr_controller(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host1", role="control"))
    )
    res = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).can_handle_nmr(node, {"compute": [], "control": [], "gateway": []})
    assert res == True


def test_nova_can_handle_nmr_1az_3hosts_0locks(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="control"))
    )
    openstack_client.return_value.compute_get_services.return_value = [
        _get_service_obj(
            {"host": "host1", "location": Munch({"zone": "nova"})}
        ),
        _get_service_obj(
            {"host": "host2", "location": Munch({"zone": "nova"})}
        ),
        _get_service_obj(
            {"host": "host3", "location": Munch({"zone": "nova"})}
        ),
    ]
    res = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).can_handle_nmr(node3, {"compute": [], "control": [], "gateway": []})
    assert res == True


def test_nova_can_handle_nmr_1az_3hosts_1locks_same_az(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    nwl.obj = {"spec": {"nodeName": "host1"}}
    openstack_client.return_value.compute_get_services.return_value = [
        _get_service_obj(
            {"host": "host1", "location": Munch({"zone": "nova"})}
        ),
        _get_service_obj(
            {"host": "host2", "location": Munch({"zone": "nova"})}
        ),
        _get_service_obj(
            {"host": "host3", "location": Munch({"zone": "nova"})}
        ),
    ]
    res = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).can_handle_nmr(node3, {"compute": [nwl], "control": [], "gateway": []})
    assert res == True


def test_nova_can_handle_nmr_1az_3hosts_1locks_different_az(
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    nwl.obj = {"spec": {"nodeName": "host1"}}
    openstack_client.return_value.compute_get_services.side_effect = (
        compute_get_services_se
    )
    res = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).can_handle_nmr(node3, {"compute": [nwl], "control": [], "gateway": []})
    assert res == False


@mock.patch("rockoon.services.LOG")
def test_nova_can_handle_nmr_1az_3hosts_1locks_skip(
    mock_log,
    mocker,
    openstack_client,
    node_maintenance_config,
    openstackdeployment_mspec,
    mock_kube_get_osdpl,
    child_view,
    nwl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    nwl.obj = {"spec": {"nodeName": "host1"}}
    openstack_client.return_value.compute_get_availability_zones.side_effect = (
        compute_get_services_se
    )
    settings.CONF["maintenance"]["respect_nova_az"] = "False"
    res = services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).can_handle_nmr(node3, {"compute": [nwl], "control": [], "gateway": []})
    assert res == True
    mock_log.info.assert_called_with(
        "The maintenance:respect_nova_az is set to False. Skip availability zones."
    )


def test_nova_process_ndr_controller(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    nwl,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="control"))
    )
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).process_ndr(node3, nwl)
    openstack_client.return_value.compute_ensure_service_disabled.assert_not_called()


def test_nova_process_ndr_compute_1instance(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    nwl,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.compute_get_all_servers.return_value = [
        _get_server_obj()
    ]
    with pytest.raises(kopf.TemporaryError):
        services.Nova(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).process_ndr(node3, nwl)
    openstack_client.return_value.compute_ensure_service_disabled.assert_called_once()


def test_nova_process_ndr_compute_no_instances(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    nwl,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.compute_ensure_service_disabled.return_value = (
        []
    )
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).process_ndr(node3, nwl)
    openstack_client.return_value.compute_get_all_servers.assert_called_once()


def test_nova_process_ndr_compute_1instance_ndr_skip_instance_check(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    nwl,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.compute_get_all_servers.return_value = [
        _get_server_obj()
    ]

    settings.CONF["maintenance"]["ndr_skip_instance_check"] = "True"
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).process_ndr(node3, nwl)
    openstack_client.return_value.compute_ensure_service_disabled.assert_called_once()
    openstack_client.return_value.compute_get_all_servers.assert_not_called()


def test_nova_cleanup_metadata_controller(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).cleanup_metadata(nwl)
    openstack_client.return_value.compute_ensure_services_absent.assert_called_once()
    openstack_client.return_value.placement_resource_provider_absent.assert_called_once()


def test_nova_cleanup_metadata_compute(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    services.Nova(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).cleanup_metadata(nwl)
    openstack_client.return_value.compute_ensure_services_absent.assert_called_once()
    openstack_client.return_value.placement_resource_provider_absent.assert_called_once()


def test_neutron_cleanup_metadata_compute(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.network_wait_agent_state = mock.Mock()
    services.Neutron(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).cleanup_metadata(nwl)
    openstack_client.return_value.network_ensure_agents_absent.assert_called_once()


def test_cinder_cleanup_metadata(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    kube_resource_list,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.volume_get_services.return_value = [
        _get_volume_service_obj({"host": "host3@lvm", "state": "down"})
    ]
    kube_resource_list.return_value = [kube.Pod(api=mock.Mock(), obj=None)]
    with mock.patch.object(kube.Pod, "exec"):
        services.Cinder(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).cleanup_metadata(nwl)
        assert (
            2 == openstack_client.return_value.volume_get_services.call_count
        )
        kube_resource_list.assert_called_once()


def test_cinder_cleanup_metadata_retry(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    kube_resource_list,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.volume_get_services.side_effect = [
        [_get_volume_service_obj({"host": "host3@lvm", "state": "up"})],
        [_get_volume_service_obj({"host": "host3@lvm", "state": "down"})],
        [_get_volume_service_obj({"host": "host3@lvm", "state": "down"})],
    ]
    kube_resource_list.return_value = [kube.Pod(api=mock.Mock(), obj=None)]
    with mock.patch.object(kube.Pod, "exec"):
        services.Cinder(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).cleanup_metadata(nwl)
        assert (
            2 == openstack_client.return_value.volume_get_services.call_count
        )
        kube_resource_list.assert_called_once()


def test_volume_remove_node_from_scheduling_no_service(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.return_value = []
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).remove_node_from_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_disabled.assert_not_called()


def test_volume_remove_node_from_scheduling_one_service(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.return_value = [
        _get_volume_service_obj({"host": "host3@lvm"})
    ]
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).remove_node_from_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_disabled.assert_called_once()


def test_volume_remove_node_from_scheduling_one_service_exception(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    nwl,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.side_effect = (
        openstack.exceptions.SDKException("foo")
    )
    with pytest.raises(kopf.TemporaryError):
        services.Cinder(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).remove_node_from_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_disabled.assert_not_called()


def test_volume_add_node_to_scheduling_one_service(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.return_value = [
        _get_volume_service_obj(
            {
                "host": "host3@lvm",
                "disabled_reason": "OSDPL: Node is under maintenance",
            }
        )
    ]
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).add_node_to_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_enabled.assert_called_once()


def test_volume_add_node_to_scheduling_no_service(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.return_value = []
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).add_node_to_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_enabled.assert_not_called()


def test_volume_add_node_to_scheduling_manually_disabled_service(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_services.return_value = [
        _get_volume_service_obj(
            {"host": "host3@lvm", "disabled_reason": "disabled by user."}
        )
    ]
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).add_node_to_scheduling(node3)
    openstack_client.return_value.volume_ensure_service_enabled.assert_not_called()


def test_volume_process_ndr_compute_1volume(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_volumes.return_value = [
        _get_volume_obj({"os-vol-host-attr:host": "host3@lvm"})
    ]
    mock_rnfs = mocker.patch.object(
        services.Cinder, "remove_node_from_scheduling"
    )
    with pytest.raises(kopf.TemporaryError):
        services.Cinder(
            openstackdeployment_mspec, logging, osdplstmock, child_view
        ).process_ndr(node3, nwl)
    mock_rnfs.assert_called_once()


def test_volume_process_ndr_compute_0volumes(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    child_view,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl = mock.Mock()
    node3 = kube.Node(
        mock.Mock, copy.deepcopy(_get_node(host="host3", role="compute"))
    )
    openstack_client.return_value.volume_get_volumes.return_value = []
    mock_rnfs = mocker.patch.object(
        services.Cinder, "remove_node_from_scheduling"
    )
    services.Cinder(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    ).process_ndr(node3, nwl)
    mock_rnfs.assert_called_once()


@pytest.mark.parametrize("service_class", get_clustered_service_classes())
def test_clustered_cleanup_persisent_data_locked(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_sts,
    service_class,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    service = service_class(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    get_child_object = mock.Mock()
    get_child_object.return_value = mock_sts
    service.get_child_object = get_child_object
    node_locked_mock = mock.Mock()
    node_locked_mock.return_value = True
    service.is_node_locked = node_locked_mock
    with pytest.raises(kopf.TemporaryError):
        service.cleanup_persistent_data(nwl)


@pytest.mark.parametrize("service_class", get_clustered_service_classes())
def test_clustered_cleanup_persisent_data_not_locked(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_sts,
    service_class,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    service = service_class(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    get_child_object = mock.Mock()
    get_child_object.return_value = mock_sts
    service.get_child_object = get_child_object
    node_locked_mock = mock.Mock()
    node_locked_mock.return_value = False
    service.is_node_locked = node_locked_mock
    service.cleanup_persistent_data(nwl)
    get_child_object.return_value.release_persistent_volume_claims.assert_called_once()


def test_redis_cleanup_persisent_data_locked(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_sts,
    kube_find,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    service = services.Redis(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    node_locked_mock = mock.Mock()
    node_locked_mock.return_value = True
    service.is_node_locked = node_locked_mock
    with pytest.raises(kopf.TemporaryError):
        service.cleanup_persistent_data(nwl)


def test_redis_cleanup_persisent_data_not_locked(
    mocker,
    openstack_client,
    openstackdeployment_mspec,
    nwl,
    child_view,
    mock_sts,
    kube_find,
    mock_kube_get_osdpl,
):
    osdplstmock = mock.Mock()
    nwl.obj = _get_nwl_obj("openstack", "host1")
    openstack_client.return_value.compute_wait_service_state = mock.Mock()
    service = services.Redis(
        openstackdeployment_mspec, logging, osdplstmock, child_view
    )
    node_locked_mock = mock.Mock()
    node_locked_mock.return_value = False
    service.is_node_locked = node_locked_mock
    service.cleanup_persistent_data(nwl)
    kube_find.return_value.release_persistent_volume_claims.assert_called_once()


# vsaienko(TODO): add more tests covering logic in _do_servers_migration()
