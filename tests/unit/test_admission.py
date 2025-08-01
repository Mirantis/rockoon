# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import json
from unittest import mock

import falcon
from falcon import testing
import pytest

from rockoon.admission import controller

api_key_encrypted = """
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIAojCIA9KqIQCAggA
nMAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECP39f0UYq4xMBIIEyFd4XvL7QyMD
eHsqIn80UxDLlkdC6xZ2Nwc/HgLQ5+rQGqssMot0HIpYd4FtgBCyCdJ6w56ndZL/
"""


# https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request
ADMISSION_REQ_JSON = """
{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "00000000-0000-0000-0000-000000000000",
        "kind": {
            "group": "lcm.mirantis.com",
            "version": "v1alpha1",
            "kind": "OpenStackDeployment"
        },
        "resource": {
            "group": "lcm.mirantis.com",
            "version": "v1alpha1",
            "resource": "openstackdeployments"
        },
        "name": "osh-dev",
        "namespace": "openstack",
        "operation": "CREATE",
        "object": {
            "apiVersion": "lcm.mirantis.com/v1alpha1",
            "kind": "OpenStackDeployment",
            "spec": {
                "openstack_version": "ussuri",
                "preset": "compute",
                "size": "tiny",
                "public_domain_name": "it.just.works",
                "features": {
                    "services": [
                       "key-manager",
                       "object-storage"
                    ],
                    "nova": {
                        "live_migration_interface": "live-int"
                    },
                    "neutron": {
                        "tunnel_interface": "neutron-tun",
                        "floating_network": {
                            "enabled": true,
                            "physnet": "physnet1"
                        }
                    },
                    "ssl": {
                        "public_endpoints": {
                            "api_key": "key",
                            "api_cert": "cert",
                            "ca_cert": "ca_cert"
                        }
                    }
                }
            },
            "status": {
                "handle": {
                    "lastStatus": "updated"
                }
            }
        },
        "oldObject": null,
        "dryRun": false
    }
}
"""

ADMISSION_REQ = json.loads(ADMISSION_REQ_JSON)

ADMISSION_REQ_STATUS = copy.deepcopy(ADMISSION_REQ)
# status change request has always requestSubResource and subResource set
ADMISSION_REQ_STATUS["request"].update(
    {
        "operation": "UPDATE",
        "requestSubResource": "status",
        "subResource": "status",
    }
)

NGS_DEVICE = {
    "device_type": "netmiko_ssh",
    "ip": "1.2.3.4",
    "username": "cisco",
}

VALUE_FROM_DICT = {
    "value_from": {
        "secret_key_ref": {"name": "secret_name", "key": "secret_key"}
    }
}


@pytest.fixture
def client():
    return testing.TestClient(controller.create_api())


@pytest.fixture
def osdpl(mocker):
    osdpl = mocker.patch("rockoon.kube.get_osdpl")
    osdpl.return_value = mock.AsyncMock()
    yield osdpl
    mocker.stopall()


@pytest.fixture
def osdplst(mocker):
    osdplst = mocker.patch("rockoon.osdplstatus.OpenStackDeploymentStatus")
    osdplst.return_value = mock.AsyncMock()
    yield osdplst
    mocker.stopall()


def test_root(client):
    response = client.simulate_get("/")
    assert response.status == falcon.HTTP_OK


def test_minimal_validation_response(client):
    req = copy.deepcopy(ADMISSION_REQ)
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_validate_invalid_request_body(client):
    req = "Boo!"
    response = client.simulate_post("/validate", body=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Exception parsing the body of request: Expecting value"
        in response.json["response"]["status"]["message"]
    )


def test_validate_not_satisfying_schema(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req.pop("apiVersion")
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "'apiVersion' is a required property"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_create_master_fail(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "master"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Using master of OpenStack is not permitted"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_upgrade_ok(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["spec"]["openstack_version"] = "train"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_upgrade_another_upgrade(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    osdplst.return_value.obj = {
        "status": {
            "openstack_version": "train",
            "osdpl": {"state": "APPLYING"},
        }
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLYING"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["spec"]["openstack_version"] = "train"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_openstack_upgrade_to_master_fail(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["spec"]["openstack_version"] = "master"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Using master of OpenStack is not permitted"
        in response.json["response"]["status"]["message"]
    )


def test_validator_single_fail(client):
    """Test that validation stops on first error"""
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    # set up for both master failure and neutron physnet required failure
    # openstack check must be called first and only its failure returned
    req["request"]["object"]["spec"]["openstack_version"] = "master"
    req["request"]["object"]["spec"]["features"]["neutron"][
        "floating_network"
    ] = {"enabled": True}
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Using master of OpenStack is not permitted"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_skiplevel_upgrade_fail(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["spec"]["openstack_version"] = "stein"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Skip-level OpenStack version upgrade is not permitted between stein and ussuri"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_downgrade_fail(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["spec"]["openstack_version"] = "train"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "downgrade is not permitted"
        in response.json["response"]["status"]["message"]
    )


def test_upgrade_with_extra_changes_fail(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["spec"]["openstack_version"] = "train"
    req["request"]["object"]["spec"]["size"] = "small"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "changing other values in the spec is not permitted"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_upgrade_on_slurp_release_ok(client, osdplst):
    allow_in = ["yoga", "zed"]
    req = copy.deepcopy(ADMISSION_REQ)
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["spec"]["openstack_version"] = "antelope"
    for os_version in allow_in:
        req["request"]["oldObject"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is True


def test_openstack_upgrade_on_slurp_release_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock
    req["request"]["operation"] = "UPDATE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["spec"]["openstack_version"] = "xena"
    req["request"]["object"]["spec"]["openstack_version"] = "antelope"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Skip-level OpenStack version upgrade is not permitted between xena and antelope"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_upgrade_with_pinned_images_fail(client):
    pinned_cases = {
        "common": {
            "openstack": {
                "values": {
                    "images": {
                        "tags": {
                            "neutron_server": "docker.io/openstackhelm/neutron:stein-ubuntu_bionic"
                        }
                    }
                }
            }
        },
        "services": {
            "dashboard": {
                "horizon": {
                    "values": {
                        "images": {
                            "tags": {
                                "horizon": "docker.io/openstackhelm/horizon:stein-ubuntu_bionic"
                            }
                        }
                    }
                }
            }
        },
    }
    for case_key, data in pinned_cases.items():
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["operation"] = "UPDATE"
        req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
        req["request"]["oldObject"]["spec"]["openstack_version"] = "train"
        req["request"]["oldObject"]["spec"][case_key] = data
        req["request"]["object"]["spec"][case_key] = data
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False
        assert response.json["response"]["status"]["code"] == 400
        assert (
            "OpenStack upgrade with pinned images is not allowed"
            in response.json["response"]["status"]["message"]
        )


def test_credentials_rotation_ok(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["status"] = {
        "credentials": {rotation_group: {"rotation_id": 1}}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_credentials_rotation_decrease_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 2}
    }
    req["request"]["object"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 1}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        f"Decreasing {rotation_group} rotation_id is not allowed"
        in response.json["response"]["status"]["message"]
    )


def test_credentials_rotation_float_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 1.1}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_credentials_rotation_zero_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 0}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_credentials_rotation_subzero_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["object"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": -1}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_credentials_rotation_remove_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 2}
    }
    req["request"]["object"]["status"]["credentials"] = {}

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        f"Removing {rotation_group} rotation config is not allowed"
        in response.json["response"]["status"]["message"]
    )


def test_credentials_rotation_increase_fail(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ_STATUS)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    rotation_group = "admin"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    req["request"]["oldObject"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 2}
    }
    req["request"]["object"]["status"]["credentials"] = {
        rotation_group: {"rotation_id": 4}
    }

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        f"Increasing {rotation_group} rotation_id more than by 1 is not allowed"
        in response.json["response"]["status"]["message"]
    )


def test_physnet_required_no_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["neutron"][
        "floating_network"
    ] = {"enabled": True}
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "physnet needs to be specified"
        in response.json["response"]["status"]["message"]
    )


def test_instance_ha_allow_in_services(client):
    allow_in = ["victoria", "wallaby", "xena", "yoga", "antelope"]
    for os_version in allow_in:
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        req["request"]["object"]["spec"]["features"]["services"].append(
            "instance-ha"
        )
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is True


def test_insance_ha_deny_in_services(client):
    deny_in = ["queens", "rocky", "stein", "train", "ussuri"]
    for os_version in deny_in:
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        req["request"]["object"]["spec"]["features"]["services"].append(
            "instance-ha"
        )
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False
        assert response.json["response"]["status"]["code"] == 400


def test_physnet_required_other_options_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["preset"] = "compute-tf"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_physnet_with_all_options_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "floating_network": {
                "network_type": "vlan",
                "segmentation_id": 4094,
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_ipsec_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"ipsec": {"enabled": True}}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_ipsec_ovn(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"backend": "ml2/ovn", "ipsec": {"enabled": True}}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_tenant_network_type_ovn(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"backend": "ml2/ovn", "tenant_network_types": ["geneve"]}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_tenant_network_type_ml2(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"backend": "ml2", "tenant_network_types": ["geneve"]}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_baremetal_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["preset"] = "compute-tf"
    req["request"]["object"]["spec"]["features"]["services"].append(
        "baremetal"
    )
    req["request"]["object"]["spec"]["features"]["ironic"] = {
        "provisioning_interface": "prov-int",
        "baremetal_network_name": "baremetal-network",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_baremetal_ovs(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["preset"] = "compute"
    req["request"]["object"]["spec"]["features"]["services"].append(
        "baremetal"
    )
    req["request"]["object"]["spec"]["features"]["ironic"] = {
        "provisioning_interface": "prov-int",
        "baremetal_network_name": "baremetal-network",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_baremetal_empty_config(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["preset"] = "compute"
    req["request"]["object"]["spec"]["features"]["services"].append(
        "baremetal"
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_baremetal_non_empty_config(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["preset"] = "compute"
    req["request"]["object"]["spec"]["features"]["services"].append(
        "baremetal"
    )
    req["request"]["object"]["spec"]["features"]["ironic"] = {
        "provisioning_interface": "prov-int",
        "baremetal_network_name": "baremetal-network",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_bgpvpn_peers(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "bgpvpn": {
                "enabled": True,
                "as_number": 64512,
                "peers": ["1.2.3.4"],
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_bgpvpn_route_reflector_enabled(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "bgpvpn": {
                "enabled": True,
                "route_reflector": {"enabled": True},
                "as_number": 64512,
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_bgpvpn_route_reflector_disabled_no_peers(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "bgpvpn": {
                "enabled": True,
                "route_reflector": {"enabled": False},
                "as_number": 64512,
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_bgpvpn_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "bgpvpn": {"enabled": True, "peers": ["1.2.3.4"]},
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_ovn_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"backend": "ml2/ovn"}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_bgpvpn_ovn(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "backend": "ml2/ovn",
            "bgpvpn": {"enabled": True, "peers": ["1.2.3.4"]},
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_vpnaas(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "vpnaas": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_vpnaas_unknown_field(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"extensions": {"vpnaas": {"enabled": True, "foo": "bar"}}}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_vpnaas_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "vpnaas": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_portprober(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "antelope"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "portprober": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_portprober_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "antelope"
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "portprober": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_portprober_old_versions(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "portprober": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_dynamic_routing(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "dynamic_routing": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_dynamic_routing_old_version(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"extensions": {"dynamic_routing": {"enabled": True}}}
    )
    for old_version in ["victoria", "wallaby", "xena"]:
        req["request"]["object"]["spec"]["openstack_version"] = old_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False
        assert response.json["response"]["status"]["code"] == 400


def test_dynamic_routing_unknown_field(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {"extensions": {"dynamic_routing": {"enabled": True, "foo": "bar"}}}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_dynamic_routing_tf(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    req["request"]["object"]["spec"].update({"preset": "compute-tf"})
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "extensions": {
                "dynamic_routing": {
                    "enabled": True,
                }
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_nova_encryption(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["nova"] = {
        "images": {"backend": "local", "encryption": {"enabled": False}},
        "live_migration_interface": "live-int",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["nova"] = {
        "images": {"backend": "local", "encryption": {"enabled": True}},
        "live_migration_interface": "live-int",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False

    req["request"]["object"]["spec"]["features"]["nova"] = {
        "images": {"backend": "lvm", "encryption": {"enabled": True}},
        "live_migration_interface": "live-int",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["nova"] = {
        "images": {"backend": "lvm", "encryption": {"enabled": False}},
        "live_migration_interface": "live-int",
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def _node_specific_request(client, node_override, result):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["nodes"] = node_override
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    if result:
        assert response.json["response"]["allowed"]
    else:
        assert response.json["response"]["allowed"] is False


def test_nodes_node_label(client):
    _node_specific_request(client, {"wrong:label": {"features": {}}}, False)
    _node_specific_request(client, {"good::label": {"services": {}}}, True)


def test_nodes_top_keys(client):
    allowed_top_keys = ["services", "features"]
    for top_key in allowed_top_keys:
        _node_specific_request(client, {"good::label": {top_key: {}}}, True)
    _node_specific_request(client, {"good::label": {"fake": {}}}, False)


def test_nodes_allowed_keys(client):
    allowed_value_override = {"chart_daemonset": {"values": {"conf": {}}}}
    allowed_services = [
        {
            "load-balancer": {"octavia": allowed_value_override},
        },
        {
            "networking": {
                "neutron": allowed_value_override,
                "openvswitch": allowed_value_override,
            }
        },
        {"metering": {"ceilometer": allowed_value_override}},
        {"metric": {"gnocchi": allowed_value_override}},
        {"compute": {"nova": allowed_value_override}},
    ]
    for service in allowed_services:
        _node_specific_request(
            client,
            {"good::label": {"services": service}},
            True,
        )


def test_nodes_wrong_key(client):
    allowed_value_override = {"chart_daemonset": {"values": {"conf": {}}}}
    wrong_service = {
        "identity": {"keystone": allowed_value_override},
    }
    _node_specific_request(
        client,
        {"good::label": {"services": wrong_service}},
        False,
    )


def test_nodes_wrong_chart_value_key(client):
    wrong_value_override = {"chart_daemonset": {"wrong": {"conf": {}}}}
    allowed_service = {
        "compute": {"nova": wrong_value_override},
    }
    _node_specific_request(
        client,
        {"good::label": {"services": allowed_service}},
        False,
    )


def test_nodes_features_top_keys(client):
    allowed_top_keys = [("neutron", {}), ("nova", {})]
    for top_key, top_value in allowed_top_keys:
        _node_specific_request(
            client, {"good::label": {"features": {top_key: {}}}}, True
        )
    _node_specific_request(
        client, {"good::label": {"features": {"fake": {}}}}, False
    )


def test_nodes_features_nova_keys(client):
    # Images valid
    for backend in ["lvm", "ceph", "local"]:
        _node_specific_request(
            client,
            {
                "good::label": {
                    "features": {
                        "nova": {
                            "images": {
                                "backend": backend,
                            }
                        }
                    }
                }
            },
            True,
        )

    # Images invalid
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "nova": {
                        "images": {
                            "backend": "invalid",
                        }
                    }
                }
            }
        },
        False,
    )

    # Encryption
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "nova": {
                        "images": {
                            "encryption": {"enabled": True},
                        }
                    }
                }
            }
        },
        True,
    )

    # live_migration interface
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {"nova": {"live_migration_interface": "live01"}}
            }
        },
        True,
    )

    # cpu mode
    _node_specific_request(
        client,
        {"good::label": {"features": {"nova": {"vcpu_type": "kvm64"}}}},
        True,
    )


def test_nodes_features_neutron_keys(client):
    neutron_required = {"dpdk": {"enabled": True, "driver": "igb_uio"}}
    _node_specific_request(
        client,
        {"good::label": {"features": {"neutron": neutron_required}}},
        True,
    )

    # Bridges valid
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bridges": [
                                {"name": "br1", "ip_address": "1.2.3.4/24"}
                            ],
                        }
                    }
                }
            }
        },
        True,
    )

    # Bridges valid additional fields
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bridges": [
                                {
                                    "name": "br1",
                                    "ip_address": "1.2.3.4/24",
                                    "additional": "",
                                }
                            ],
                        }
                    }
                }
            }
        },
        True,
    )

    # Bridges missing IP
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bridges": [{"name": "br1"}],
                        }
                    }
                }
            }
        },
        False,
    )

    # Bonds valid
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bonds": [
                                {
                                    "name": "foo",
                                    "bridge": "br1",
                                    "nics": [
                                        {"name": "br1", "pci_id": "1.2.3:00.1"}
                                    ],
                                }
                            ],
                        }
                    }
                }
            }
        },
        True,
    )

    # Bonds valid additional fields
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bonds": [
                                {
                                    "name": "foo",
                                    "bridge": "br1",
                                    "nics": [
                                        {
                                            "name": "br1",
                                            "pci_id": "1.2.3:00.1",
                                            "additional": "option",
                                        }
                                    ],
                                }
                            ],
                        },
                        "tunnel_interface": "br-phy",
                    }
                }
            }
        },
        True,
    )

    # Bonds Missing PCI_ID
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "dpdk": {
                            "enabled": True,
                            "driver": "igb_uio",
                            "bonds": [
                                {
                                    "name": "foo",
                                    "bridge": "br1",
                                    "nics": [{"name": "br1"}],
                                }
                            ],
                        }
                    }
                }
            }
        },
        False,
    )


def test_nodes_features_neutron_sriov_keys(client):
    neutron_required = {"sriov": {"enabled": True}}
    _node_specific_request(
        client,
        {"good::label": {"features": {"neutron": neutron_required}}},
        True,
    )
    # nics valid
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "sriov": {
                            "enabled": True,
                            "nics": [
                                {
                                    "device": "enp1",
                                    "num_vfs": 32,
                                    "physnet": "tenant",
                                }
                            ],
                        }
                    }
                }
            }
        },
        True,
    )
    # nics valid additional fields
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "sriov": {
                            "enabled": True,
                            "nics": [
                                {
                                    "device": "enp1",
                                    "num_vfs": 32,
                                    "hooks": {"init": "echo 'Init hook'"},
                                    "physnet": "tenant",
                                    "mtu": 1500,
                                    "trusted": "true",
                                }
                            ],
                        }
                    }
                }
            }
        },
        True,
    )
    # NICS missing num_vfs
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "neutron": {
                        "sriov": {
                            "enabled": True,
                            "nics": [
                                {
                                    "device": "enp1",
                                    "physnet": "tenant",
                                }
                            ],
                        }
                    }
                }
            }
        },
        False,
    )


def test_nodes_features_cinder_keys(client):
    cinder_required = {
        "volume": {"backends": {"lvm_backend": {"lvm": {"option": "value"}}}}
    }
    _node_specific_request(
        client,
        {"good::label": {"features": {"cinder": cinder_required}}},
        True,
    )
    # backend valid
    _node_specific_request(
        client,
        {
            "good::label": {
                "features": {
                    "cinder": {
                        "volume": {
                            "backends": {
                                "lvm_fast": {
                                    "lvm": {"foo": "bar"},
                                },
                                "lvm_slow": {
                                    "lvm": {"foo": "baz"},
                                },
                            }
                        }
                    }
                }
            }
        },
        True,
    )


def test_glance_signature(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "signature": {"enabled": True}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["glance"] = {
        "signature": {"enabled": True, "certificate_validation": True}
    }

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["glance"] = {
        "signature": {"enabled": False, "certificate_validation": True}
    }

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_glance_features_cinder_keys(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "cinder": {
                "backend1": {"default": True, "backend_name": "lvm:fast"}
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "cinder": {
                "backend1": {"default": True, "cinder_volume_type": "fast"}
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_glance_features_multiple_backends_ok(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "cinder": {
                "backend1": {"default": True, "backend_name": "lvm:fast"},
                "backend2": {"backend_name": "lvm:fast"},
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_glance_features_multiple_defaults(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "cinder": {
                "backend1": {"default": True, "backend_name": "lvm:fast"},
                "backend2": {"default": True, "backend_name": "lvm:fast"},
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_glance_features_cinder_missing_mandatory(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {"cinder": {"backend1": {"backend_name": "lvm:fast"}}}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False

    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {"cinder": {"backend1": {"default": True}}}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False

    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {"cinder": {"backend1": {"default": True}}}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_glance_features_cinder_invalid_backend_name(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "cinder": {
                "backend1": {"default": True, "backend_name": "lvmfast"}
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_glance_features_cinder_missing_default(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {"cinder": {"backend1": {"backend_name": "lvm:fast"}}}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_glance_features_file_good(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "file": {
                "backend1": {
                    "default": True,
                    "pvc": {
                        "size": "1Gi",
                        "storage_class_name": "foo",
                    },
                }
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_glance_features_file_good_missing_madatory(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["glance"] = {
        "backends": {
            "file": {
                "backend1": {
                    "default": True,
                    "pvc": {"size": "1Gi"},
                }
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_barbican_features_namespace_before_victoria(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["barbican"] = {
        "backends": {"vault": {"enabled": True, "namespace": "spam"}}
    }
    req["request"]["object"]["spec"]["openstack_version"] = "ussuri"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_barbican_features_fields_ok(client):
    allowed_vault_fileds = [
        ("enabled", True),
        ("approle_role_id", "role"),
        ("approle_secret_id", "secret"),
        ("vault_url", "url"),
        ("namespace", "namespace"),
        ("kv_mountpoint", "mountpoint"),
        ("use_ssl", False),
        ("ssl_ca_crt_file", "content"),
    ]

    for field, value in allowed_vault_fileds:
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["object"]["spec"]["features"]["barbican"] = {
            "backends": {"vault": {field: value}}
        }
        req["request"]["object"]["spec"]["openstack_version"] = "victoria"
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is True


def test_barbican_features_fields_unknown(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["barbican"] = {
        "backends": {"vault": {"foo": "bar"}}
    }
    req["request"]["object"]["spec"]["openstack_version"] = "victoria"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_barbican_features_fields_value_from_fail(client):
    allowed_vault_fileds = [
        ("vault_url", VALUE_FROM_DICT),
        ("approle_role_id", {"incorrect": "obj"}),
        ("approle_secret_id", {"incorrect": "obj"}),
    ]
    for field, value in allowed_vault_fileds:
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["object"]["spec"]["features"]["barbican"] = {
            "backends": {"vault": {field: value}}
        }
        req["request"]["object"]["spec"]["openstack_version"] = "victoria"
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False
        assert response.json["response"]["status"]["code"] == 400


def test_barbican_features_fields_value_from_ok(client):
    allowed_vault_fileds = [
        ("approle_role_id", VALUE_FROM_DICT),
        ("approle_secret_id", VALUE_FROM_DICT),
    ]
    for field, value in allowed_vault_fileds:
        req = copy.deepcopy(ADMISSION_REQ)
        req["request"]["object"]["spec"]["features"]["barbican"] = {
            "backends": {"vault": {field: value}}
        }
        req["request"]["object"]["spec"]["openstack_version"] = "victoria"
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is True


def test_nova_features_vcpu_type(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["nova"].update(
        {"vcpu_type": "spam,ham"}
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_nova_features_vcpu_type_host_mode_not_alone(client):
    req = copy.deepcopy(ADMISSION_REQ)
    for t in ("host-model", "host-passthrough"):
        req["request"]["object"]["spec"]["features"]["nova"] = {
            "vcpu_type": f"spam,ham,{t}"
        }
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False, t
        assert response.json["response"]["status"]["code"] == 400


def test_nova_features_vcpu_type_multiple_stein_or_older(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["nova"] = {
        "vcpu_type": "spam,ham"
    }
    for ver in ("queens", "rocky", "stein"):
        req["request"]["object"]["spec"]["openstack_version"] = ver
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is False, ver
        assert response.json["response"]["status"]["code"] == 400


def test_panko_install_ok(client):
    allow_in = [
        "queens",
        "rocky",
        "stein",
        "train",
        "ussuri",
        "victoria",
        "wallaby",
    ]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["services"].append("event")
    for os_version in allow_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is True
        ), "Event service (Panko) was retired and is not available since OpenStack Xena release."


def test_panko_install_fail(client):
    deny_in = ["xena", "yoga", "antelope", "master"]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["services"].append("event")
    for os_version in deny_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is False
        ), "Event service (Panko) was retired and is not available since OpenStack Xena release."
        assert response.json["response"]["status"]["code"] == 400


def test_openstack_delete_ok(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPLIED"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPLIED"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    req["request"]["operation"] = "DELETE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_delete_not_allowed(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    osdplst.return_value.obj = {
        "status": {"openstack_version": "train", "osdpl": {"state": "APPYING"}}
    }
    get_osdpl_status_mock = mock.Mock()
    get_osdpl_status_mock.return_value = "APPYING"
    osdplst.return_value.get_osdpl_status = get_osdpl_status_mock

    req["request"]["operation"] = "DELETE"
    req["request"]["oldObject"] = copy.deepcopy(req["request"]["object"])
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_openstack_encrypted_api_key(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["ssl"][
        "public_endpoints"
    ].update({"api_key": api_key_encrypted})
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "Encrypted SSL key is not allowed yet"
        in response.json["response"]["status"]["message"]
    )


def test_keystone_domains_old_format(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "domain_specific_configuration": {
            "enabled": True,
            "domains": [
                {"name": "test", "enabled": True, "config": {"foo": "bar"}}
            ],
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_keystone_domains_new_format(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "domain_specific_configuration": {
            "enabled": True,
            "ks_domains": {
                "test": {"enabled": True, "config": {"foo": "bar"}}
            },
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_keystone_domains_new_format_missing_key(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "domain_specific_configuration": {
            "enabled": True,
            "ks_domains": {"test": {"config": {"foo": "bar"}}},
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_keystone_domains_new_format_old_format(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "domain_specific_configuration": {
            "enabled": True,
            "ks_domains": {
                "test": {"enabled": True, "config": {"foo": "bar"}}
            },
            "domains": [
                {"name": "test", "enabled": True, "config": {"foo": "bar"}}
            ],
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_neutron_ngs_old_format(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    ngs_device = copy.deepcopy(NGS_DEVICE)
    ngs_device["name"] = "cisco-switch"
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "baremetal": {
                "ngs": {"devices": [ngs_device]},
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_neutron_ngs_new_format(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    ngs_device = copy.deepcopy(NGS_DEVICE)
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "baremetal": {
                "ngs": {"hardware": {"cisco-switch": ngs_device}},
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_neutron_ngs_both_formats(client, osdplst):
    req = copy.deepcopy(ADMISSION_REQ)
    ngs_device = copy.deepcopy(NGS_DEVICE)
    ngs_device_old = copy.deepcopy(NGS_DEVICE)
    ngs_device_old["name"] = "cisco-switch"
    req["request"]["object"]["spec"]["features"]["neutron"].update(
        {
            "baremetal": {
                "ngs": {
                    "hardware": {"cisco-switch": ngs_device},
                    "devices": [ngs_device_old],
                },
            }
        }
    )
    response = client.simulate_post("/validate", json=req)
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_neutron_ngs_value_from(client, osdplst):
    allowed_fields = [
        ("password", "string"),
        ("password", VALUE_FROM_DICT),
        ("ssh_private_key", "string"),
        ("ssh_private_key", VALUE_FROM_DICT),
        ("secret", "string"),
        ("secret", VALUE_FROM_DICT),
    ]
    for field, value in allowed_fields:
        req = copy.deepcopy(ADMISSION_REQ)
        ngs_device = copy.deepcopy(NGS_DEVICE)
        ngs_device.update({field: value})
        req["request"]["object"]["spec"]["features"]["neutron"].update(
            {
                "baremetal": {
                    "ngs": {"hardware": {"cisco-switch": ngs_device}},
                }
            }
        )
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert response.json["response"]["allowed"] is True


def test_ovn_before_yoga(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["neutron"] = {
        "backend": "ml2/ovn"
    }
    req["request"]["object"]["spec"]["openstack_version"] = "victoria"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["status"]["code"] == 400
    assert response.json["response"]["allowed"] is False


def test_ovn_yoga(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["neutron"] = {
        "backend": "ml2/ovn",
        "tunnel_interface": "tunnel",
    }
    req["request"]["object"]["spec"]["openstack_version"] = "yoga"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_db_backup_backend_nfs_opts_incorrect(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {"enabled": True, "backend": "pv_nfs"}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400
    assert (
        "When backup backend is set to pv_nfs, pv_nfs.server and pv_nfs.path options are required"
        in response.json["response"]["status"]["message"]
    )


def test_db_backup_backend_nfs_opts_correct(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "backend": "pv_nfs",
            "pv_nfs": {"server": "1.2.3.4", "path": "/share"},
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_db_backup_backend_default_opts_correct(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "backend": "pvc",
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_db_backup_sync_remote_incorrect(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "ceph_mariadb": {
                        "conf": {
                            "type": "s3",
                            "provider": "Ceph",
                            "endpoint": "https://rgw.endpoint.tst",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    }
                },
            },
        }
    }
    required_fields = "['conf', 'path']"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        f"Remote ceph_mariadb fields {required_fields} are mandatory"
        in response.json["response"]["status"]["message"]
    )


def test_db_backup_sync_ceph_conf_correct(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "ceph_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "Ceph",
                            "endpoint": "https://rgw.endpoint.tst",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    }
                },
            },
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_db_backup_sync_aws_conf_correct(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "aws_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "AWS",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    }
                },
            },
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_db_backup_sync_ceph_conf_incorrect(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "ceph_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "Ceph",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    }
                },
            },
        }
    }
    required_fields = "['type', 'provider', 'access_key_id', 'secret_access_key', 'endpoint']"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        f"Remote ceph_mariadb section conf fields {required_fields} are mandatory"
        in response.json["response"]["status"]["message"]
    )


def test_db_backup_sync_aws_conf_incorrect(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "aws_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "AWS",
                            "secret_access_key": "10111213",
                        },
                    }
                },
            },
        }
    }
    required_fields = (
        "['type', 'provider', 'access_key_id', 'secret_access_key']"
    )
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        f"Remote aws_mariadb section conf fields {required_fields} are mandatory"
        in response.json["response"]["status"]["message"]
    )


def test_db_backup_sync_remotes_not_allowed(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {
            "enabled": True,
            "sync_remote": {
                "enabled": True,
                "remotes": {
                    "ceph_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "Ceph",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    },
                    "aws_mariadb": {
                        "path": "testbucket/backups",
                        "conf": {
                            "type": "s3",
                            "provider": "AWS",
                            "access_key_id": "12345678",
                            "secret_access_key": "10111213",
                        },
                    },
                },
            },
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "Only one remote is allowed in remotes section"
        in response.json["response"]["status"]["message"]
    )


def test_cron_validation(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["database"] = {
        "backup": {"enabled": True, "schedule_time": "05-40 */05 07 Jan mon"}
    }

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True

    req["request"]["object"]["spec"]["features"]["database"] = {
        "cleanup": {"heat": {"schedule": "22 06 15 17 *"}}
    }

    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert response.json["response"]["status"]["code"] == 400


def test_manila_install_ok(client):
    allow_in = ["yoga", "antelope"]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["services"].append(
        "shared-file-system"
    )
    for os_version in allow_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is True
        ), "Shared Filesystems (Manila) does not supported in OpenStack version before Yoga release."


def test_manila_install_fail(client):
    deny_in = [
        "queens",
        "rocky",
        "stein",
        "train",
        "ussuri",
        "victoria",
        "wallaby",
        "xena",
    ]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["services"].append(
        "shared-file-system"
    )
    for os_version in deny_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is False
        ), "Shared Filesystems (Manila) does not supported in OpenStack version before Yoga release."
        assert response.json["response"]["status"]["code"] == 400


def test_manila_install_fail_with_TF(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["services"].append(
        "shared-file-system"
    )
    req["request"]["object"]["spec"]["preset"] = "compute-tf"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert (
        response.json["response"]["allowed"] is False
    ), "Shared Filesystems (Manila) services is not supported with TungstenFabric networking."
    assert response.json["response"]["status"]["code"] == 400


def test_openstack_create_osdpl_fail(client, osdpl):
    req = copy.deepcopy(ADMISSION_REQ)
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "OpenStackDeployment already exist in namespace"
        in response.json["response"]["status"]["message"]
    )


def test_cinder_buckup_drivers_ok(client):
    allow_in = ["yoga", "antelope"]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["cinder"] = {
        "backup": {
            "enabled": False,
            "drivers": {
                "testdriver": {
                    "type": "s3",
                    "enabled": True,
                    "endpoint_url": "http://test.me",
                    "store_bucket": "test",
                    "store_access_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "key": "ak",
                                "name": "secret_name",
                            }
                        }
                    },
                    "store_secret_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "key": "sk",
                                "name": "secret_name",
                            }
                        }
                    },
                }
            },
        }
    }
    for os_version in allow_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is True
        ), "Custom Cinder backup driver is allowed from Yoga release."


def test_cinder_buckup_drivers_fail(client):
    deny_in = [
        "queens",
        "rocky",
        "stein",
        "train",
        "ussuri",
        "victoria",
        "wallaby",
        "xena",
    ]
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["cinder"] = {
        "backup": {
            "enabled": False,
            "drivers": {
                "testdriver": {
                    "type": "s3",
                    "enabled": True,
                    "endpoint_url": "http://test.me",
                    "store_bucket": "test",
                    "store_access_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "key": "ak",
                                "name": "secret_name",
                            }
                        }
                    },
                    "store_secret_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "key": "sk",
                                "name": "secret_name",
                            }
                        }
                    },
                }
            },
        }
    }
    for os_version in deny_in:
        req["request"]["object"]["spec"]["openstack_version"] = os_version
        response = client.simulate_post("/validate", json=req)
        assert response.status == falcon.HTTP_OK
        assert (
            response.json["response"]["allowed"] is False
        ), "Custom Cinder backup driver is allowed from Yoga release."
        assert response.json["response"]["status"]["code"] == 400


def _cinder_extra_backend_specific_request(client, backends_conf, result):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["cinder"] = {
        "volume": {"backends": backends_conf}
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    if result:
        assert response.json["response"]["allowed"]
    else:
        assert response.json["response"]["allowed"] is False


def test_cinder_extra_backends_sts(client):
    # Configs are valid
    _cinder_extra_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {
                        "cinder": {
                            "DEFAULT": {"enabled_backends": "foo"},
                            "foo": {
                                "volume_backend_name": "bar",
                                "volume_driver": "drv",
                            },
                        },
                    },
                    "images": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "create_volume_type": True,
                "enabled": True,
                "type": "statefulset",
            },
        },
        True,
    )

    # Configs are invalid
    #   Extra key in values
    _cinder_extra_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "bootstrap": {"foo": "bar"},
                    "conf": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "statefulset",
            },
        },
        False,
    )

    #   unsupported backend type
    _cinder_extra_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "deployment",
            },
        },
        False,
    )

    #   incorrect backend configuration
    _cinder_extra_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {
                        "cinder": {
                            "DEFAULT": {"enabled_backends": "baz"},
                            "foo": {
                                "volume_backend_name": "bar",
                                "volume_driver": "drv",
                            },
                        },
                    },
                    "images": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "create_volume_type": True,
                "enabled": True,
                "type": "statefulset",
            },
        },
        False,
    )


def _manila_backend_specific_request(client, backends_conf, result):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["manila"] = {
        "share": {"backends": backends_conf}
    }
    req["request"]["object"]["spec"]["features"]["services"].append(
        "shared-file-system"
    )
    req["request"]["object"]["spec"]["openstack_version"] = "caracal"
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    if result:
        assert response.json["response"]["allowed"]
    else:
        assert response.json["response"]["allowed"] is False


def test_manila_backends_sts(client):
    # Configs are valid
    _manila_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {
                        "manila": {
                            "DEFAULT": {"enabled_share_backends": "foo"},
                            "foo": {
                                "share_backend_name": "bar",
                                "share_driver": "drv",
                            },
                        },
                    },
                    "images": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "statefulset",
            },
        },
        True,
    )

    # Configs are invalid
    #   Extra key in values
    _manila_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "bootstrap": {"foo": "bar"},
                    "conf": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "statefulset",
            },
        },
        False,
    )

    #   unsupported backend type
    _manila_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "deployment",
            },
        },
        False,
    )

    #   incorrect backend configuration
    _manila_backend_specific_request(
        client,
        {
            "backend-1": {
                "values": {
                    "conf": {
                        "manila": {
                            "DEFAULT": {"enabled_share_backends": "baz"},
                            "foo": {
                                "share_backend_name": "bar",
                                "share_driver": "drv",
                            },
                        },
                    },
                    "images": {"foo": "bar"},
                    "labels": {"foo": "bar"},
                    "pod": {"foo": "bar"},
                },
                "enabled": True,
                "type": "statefulset",
            },
        },
        False,
    )


def test_openstack_keystone_keycloak_providers_not_allowed(
    client, federation_provider
):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "keycloak": {
            "url": "http://mykeycloak.it.just.works",
            "enabled": True,
        },
        "federation": {
            "openid": {
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1},
            }
        },
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "Use one of keystone:keycloack or keystone:federation section"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_keystone_keycloak_disabled_providers(
    client, federation_provider
):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "keycloak": {
            "url": "http://mykeycloak.it.just.works",
            "enabled": False,
        },
        "federation": {
            "openid": {
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1},
            }
        },
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_keystone_providers_one(client, federation_provider):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1},
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_keystone_providers_one_optional_fields(
    client, federation_provider
):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    provider1.update(
        {"mapping": [{"my": "mapping"}], "oauth2": {"foo": "bar"}}
    )
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1},
                "oidc_auth_type": "oauth2",
            }
        }
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_keystone_two_oauth2_providers(client, federation_provider):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    provider2 = copy.deepcopy(federation_provider)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "federation": {
            "openid": {
                "oidc_auth_type": "oauth2",
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1, "provider2": provider2},
            }
        },
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_keystone_two_oauth20_providers(client, federation_provider):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = federation_provider
    provider2 = copy.deepcopy(federation_provider)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "federation": {
            "openid": {
                "oidc_auth_type": "oauth20",
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1, "provider2": provider2},
            }
        },
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "Multiple oidc providers supperted only with oauth2 type"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_keystone_two_providers_default_not_allowed(
    client, federation_provider
):
    req = copy.deepcopy(ADMISSION_REQ)
    provider1 = copy.deepcopy(federation_provider)
    provider2 = copy.deepcopy(federation_provider)
    req["request"]["object"]["spec"]["features"]["keystone"] = {
        "federation": {
            "openid": {
                "enabled": True,
                "oidc": {"OIDCFOO": "OIDCBAR"},
                "providers": {"provider1": provider1, "provider2": provider2},
            }
        },
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "Multiple oidc providers supperted only with oauth2 type"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_hortizon_additional_theme(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["horizon"] = {
        "themes": [
            {
                "url": "https://foo.bar/themea.tar.gz",
                "description": "themeA",
                "name": "themeA",
                "sha256summ": "123456",
            }
        ]
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True


def test_openstack_hortizon_additiona_theme_missing_keys(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["horizon"] = {
        "themes": [
            {
                "description": "themeA",
                "name": "themeA",
            }
        ]
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is False
    assert (
        "Horion theme is missing mandatory keys"
        in response.json["response"]["status"]["message"]
    )


def test_openstack_hortizon_mirantis_disabled(client):
    req = copy.deepcopy(ADMISSION_REQ)
    req["request"]["object"]["spec"]["features"]["horizon"] = {
        "themes": [
            {
                "name": "mirantis",
                "enabled": False,
            }
        ]
    }
    response = client.simulate_post("/validate", json=req)
    assert response.status == falcon.HTTP_OK
    assert response.json["response"]["allowed"] is True
