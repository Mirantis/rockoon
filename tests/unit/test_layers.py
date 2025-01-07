import copy
import json
import logging
import yaml
from unittest import mock

import kopf
import pytest

from rockoon import constants, layers


CREDS_KWARGS = {
    "ssh_credentials": {"private": "", "public": ""},
    "credentials": [
        {
            "memcached": "",
            "database": {"user": {"username": "", "password": ""}},
            "messaging": {"user": {"username": "", "password": ""}},
            "notifications": {"user": {"username": "", "password": ""}},
            "identity": {"user": {"username": "", "password": ""}},
        }
    ],
    "admin_creds": {
        "database": {"username": "", "password": ""},
        "identity": {"password": "", "username": ""},
        "messaging": {"password": "", "username": ""},
    },
    "guest_creds": {
        "password": "",
    },
    "ceph": {
        "nova": {"username": "", "secrets": "", "keyring": "", "pools": {}}
    },
    "libvirt_vnc_certs": {
        "ca_cert": "",
        "server_cert": "",
        "server_key": "",
        "client_cert": "",
        "client_key": "",
    },
    "keystone_creds": {},
}


def test_apply_list_empty_stein(osdpl_min_stein):
    compute_services = {
        "block-storage",
        "compute",
        "dns",
        "placement",
        "identity",
        "dashboard",
        "descheduler",
        "image",
        "ingress",
        "database",
        "memcached",
        "networking",
        "orchestration",
        "messaging",
        "load-balancer",
        "coordination",
        "key-manager",
        "redis",
        "dynamic-resource-balancer",
    }
    ta, td = layers.services(osdpl_min_stein, mock.Mock())
    assert ta == compute_services
    assert not td


def test_apply_list_empty_train(osdpl_min_train):
    compute_services = {
        "block-storage",
        "compute",
        "dns",
        "placement",
        "identity",
        "dashboard",
        "descheduler",
        "image",
        "ingress",
        "database",
        "memcached",
        "networking",
        "orchestration",
        "messaging",
        "load-balancer",
        "coordination",
        "key-manager",
        "redis",
        "dynamic-resource-balancer",
    }
    ta, td = layers.services(osdpl_min_train, mock.Mock())
    assert ta == compute_services
    assert not td


def test_apply_list_empty_rocky(osdpl_min_rocky):
    compute_services = {
        "block-storage",
        "compute",
        "dns",
        "identity",
        "dashboard",
        "image",
        "ingress",
        "database",
        "descheduler",
        "memcached",
        "networking",
        "orchestration",
        "messaging",
        "load-balancer",
        "coordination",
        "key-manager",
        "redis",
        "dynamic-resource-balancer",
    }
    ta, td = layers.services(osdpl_min_rocky, mock.Mock())
    assert ta == compute_services
    assert not td


def test_apply_list_not_empty(openstackdeployment_mspec):
    ta, td = layers.services(openstackdeployment_mspec, mock.Mock())
    assert "compute" in ta
    assert not td


def test_fail_render_template_with_incorrect_release(
    openstackdeployment_mspec,
):
    openstackdeployment_mspec["openstack_version"] = "fake"
    render = lambda: layers.render_service_template(
        "compute",
        openstackdeployment_mspec,
        logging,
    )
    pytest.raises(Exception, render, match="Template not found")


def test_render_template(openstackdeployment_mspec):
    images_mock = mock.Mock()
    images_mock = ["a", "b"]
    data = layers.render_service_template(
        "compute",
        openstackdeployment_mspec,
        logging,
        credentials=[
            {
                "memcached": "",
                "database": {"user": {"username": "", "password": ""}},
                "messaging": {"user": {"username": "", "password": ""}},
                "notifications": {"user": {"username": "", "password": ""}},
                "identity": {"user": {"username": "", "password": ""}},
            },
        ],
        admin_creds=mock.Mock(),
        guest_creds=mock.Mock(),
        images=images_mock,
        keystone_creds={},
        ceph={
            "nova": {
                "pools": {},
                "username": "nova",
                "keyring": "nova",
                "secrets": "nova",
            }
        },
        ssh_credentials={
            "private": "nova_private_key",
            "public": "nova_public_key",
        },
        libvirt_vnc_certs={
            "ca_cert": "",
            "server_cert": "",
            "server_key": "",
            "client_cert": "",
            "client_key": "",
        },
    )
    assert len(data) == 1 and "spec" in data


@mock.patch.object(layers, "render_service_template")
def test_merge_all_no_modification(
    rst,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    compute_helmbundle["spec"]["repositories"] = []

    # nullify merge points for openstackdeployment
    openstackdeployment_mspec["common"]["openstack"]["values"] = {}
    openstackdeployment_mspec["services"]["compute"] = {}

    rst.return_value = compute_helmbundle
    compute_helmbundle = copy.deepcopy(compute_helmbundle)
    result = layers.merge_all_layers(
        "compute",
        openstackdeployment_mspec,
        logging,
    )
    assert id(result) != id(compute_helmbundle)
    assert result == compute_helmbundle


@mock.patch.object(layers, "render_service_template")
def test_merge_all_prioritize_service_values_over_common_group_values(
    rst,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    # let's nova chart has some config values
    compute_helmbundle["spec"]["releases"][2]["values"] = {"test0": 0}
    # and others charts are empty
    for i in range(2):
        compute_helmbundle["spec"]["releases"][i]["values"] = {}
    rst.return_value = compute_helmbundle

    openstackdeployment_mspec["common"]["charts"]["repositories"] = []
    openstackdeployment_mspec["common"]["charts"]["releases"]["values"] = {}
    # this overrides are for nova only
    # as rabbitmq and libvirt are not in openstack group
    openstackdeployment_mspec["common"]["openstack"]["values"] = {
        "test1": 1,
        "test2": 2,
    }
    openstackdeployment_mspec["services"]["compute"]["nova"]["values"] = {
        "test2": 3,
        "test3": 4,
    }
    result = layers.merge_all_layers(
        "compute",
        openstackdeployment_mspec,
        logging,
    )
    # rabbitmq and libvirt
    for i in range(2):
        assert result["spec"]["releases"][i]["values"] == {}
    # nova
    assert result["spec"]["releases"][2]["values"] == {
        "test0": 0,
        "test1": 1,
        "test2": 3,
        "test3": 4,
    }


@mock.patch.object(layers, "render_service_template")
def test_merge_all_prioritize_group_releases_over_chart_releases(
    rst,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    # let's nova chart has some config values
    compute_helmbundle["spec"]["releases"][2]["values"] = {
        "test0": 0,
        "test0_r": "bundle",
    }
    # and others charts are empty
    for i in range(2):
        compute_helmbundle["spec"]["releases"][i]["values"] = {}
    rst.return_value = compute_helmbundle

    openstackdeployment_mspec["common"]["charts"]["repositories"] = []
    openstackdeployment_mspec["common"]["charts"]["releases"]["values"] = {}
    openstackdeployment_mspec["services"]["compute"]["nova"] = {
        "values": {"test0_r": "osdpl"}
    }
    # helmbundle values will be overriden by common.chart.releases
    # for all charts
    openstackdeployment_mspec["common"]["charts"]["releases"]["values"] = {
        "test1": 1,
        "test2": 2,
    }
    # and then overrides for nova only
    openstackdeployment_mspec["common"]["openstack"] = {
        "releases": {"values": {"test2": 3, "test3": 4}}
    }
    result = layers.merge_all_layers(
        "compute",
        openstackdeployment_mspec,
        logging,
    )
    # rabbitmq and libvirt
    for i in range(2):
        assert result["spec"]["releases"][i]["values"] == {
            "test1": 1,
            "test2": 2,
        }
    # nova
    assert result["spec"]["releases"][2]["values"] == {
        "test0": 0,
        "test1": 1,
        "test2": 3,
        "test3": 4,
        "test0_r": "osdpl",
    }


@mock.patch.object(layers, "render_service_template")
def test_merge_all_type_conflict(
    rst,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    openstackdeployment_mspec["services"]["compute"]["nova"]["values"][
        "conf"
    ] = {"ceph": {"enabled": None}}
    rst.return_value = compute_helmbundle
    with pytest.raises(kopf.PermanentError, match="conf:ceph:enabled"):
        layers.merge_all_layers(
            "compute",
            openstackdeployment_mspec,
            logging,
        )


@mock.patch.object(layers, "LOG")
def test_merge_all_float_int(
    mock_log,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    openstackdeployment_mspec["common"]["charts"]["releases"]["values"] = {
        "conf": {"nova": {"scheduler": {"ram_weight_multiplier": 1.0}}}
    }
    openstackdeployment_mspec["services"]["compute"]["nova"]["values"][
        "conf"
    ] = {"nova": {"scheduler": {"ram_weight_multiplier": 2}}}
    helmbundle = layers.merge_all_layers(
        "compute",
        openstackdeployment_mspec,
        logging,
        **CREDS_KWARGS,
    )
    assert (
        helmbundle["spec"]["releases"][2]["values"]["conf"]["nova"][
            "scheduler"
        ]["ram_weight_multiplier"]
        == 2
    )
    mock_log.assert_not_called()


@mock.patch.object(layers, "LOG")
def test_merge_all_nodes(
    mock_log,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    openstackdeployment_mspec["nodes"] = {
        "mylabel::myvalue": {
            "services": {
                "compute": {
                    "nova": {
                        "nova_compute": {
                            "values": {
                                "root_override": "root",
                                "conf": {"nova": {"DEFAULT": {"foo": "bar"}}},
                            }
                        }
                    }
                }
            }
        }
    }
    helmbundle = layers.merge_all_layers(
        "compute",
        openstackdeployment_mspec,
        logging,
        **CREDS_KWARGS,
    )
    assert helmbundle["spec"]["releases"][2]["values"]["overrides"][
        "nova_compute"
    ]["labels"]["mylabel::myvalue"]["values"] == {
        "conf": {"nova": {"DEFAULT": {"foo": "bar"}}},
        "root_override": "root",
    }
    mock_log.assert_not_called()


@mock.patch.object(layers, "LOG")
def test_merge_all_nodes_multiple_labels(
    mock_log,
    openstackdeployment_mspec,
    compute_helmbundle,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    openstackdeployment_mspec["nodes"] = {
        "mylabel::myvalue": {
            "services": {
                "networking": {
                    "openvswitch": {
                        "openvswitch-db": {
                            "values": {
                                "root_override": "root",
                                "conf": {"openvswitch": {"foo": "bar"}},
                            }
                        }
                    },
                    "neutron": {
                        "ovs-agent": {
                            "values": {
                                "root_override": "root-ovs-agent",
                                "conf": {
                                    "neutron": {"DEFAULT": {"foo": "ovs"}}
                                },
                            }
                        },
                        "l3-agent": {
                            "values": {
                                "root_override": "root-l3-agent",
                                "conf": {
                                    "neutron": {"DEFAULT": {"foo": "l3"}}
                                },
                            }
                        },
                    },
                }
            }
        },
        "mylabel2::myvalue": {
            "services": {
                "networking": {
                    "neutron": {
                        "ovs-agent": {
                            "values": {
                                "root_override": "root-ovs-agent-2",
                                "conf": {
                                    "neutron": {"DEFAULT": {"foo": "ovs-2"}}
                                },
                            }
                        },
                        "l3-agent": {
                            "values": {
                                "root_override": "root-l3-agent-2",
                                "conf": {
                                    "neutron": {"DEFAULT": {"foo": "l3-2"}}
                                },
                            }
                        },
                    }
                }
            }
        },
    }
    helmbundle = layers.merge_all_layers(
        "networking",
        openstackdeployment_mspec,
        logging,
        **CREDS_KWARGS,
    )
    assert helmbundle["spec"]["releases"][2]["values"]["overrides"][
        "ovs-agent"
    ]["labels"]["mylabel::myvalue"]["values"] == {
        "conf": {"neutron": {"DEFAULT": {"foo": "ovs"}}},
        "root_override": "root-ovs-agent",
    }
    assert helmbundle["spec"]["releases"][1]["values"]["overrides"][
        "openvswitch-db"
    ]["labels"]["mylabel::myvalue"]["values"] == {
        "conf": {"openvswitch": {"foo": "bar"}},
        "root_override": "root",
    }
    assert helmbundle["spec"]["releases"][2]["values"]["overrides"][
        "ovs-agent"
    ]["labels"]["mylabel2::myvalue"]["values"] == {
        "conf": {"neutron": {"DEFAULT": {"foo": "ovs-2"}}},
        "root_override": "root-ovs-agent-2",
    }
    assert helmbundle["spec"]["releases"][2]["values"]["overrides"][
        "l3-agent"
    ]["labels"]["mylabel::myvalue"]["values"] == {
        "conf": {"neutron": {"DEFAULT": {"foo": "l3"}}},
        "root_override": "root-l3-agent",
    }
    assert helmbundle["spec"]["releases"][2]["values"]["overrides"][
        "l3-agent"
    ]["labels"]["mylabel2::myvalue"]["values"] == {
        "conf": {"neutron": {"DEFAULT": {"foo": "l3-2"}}},
        "root_override": "root-l3-agent-2",
    }
    assert (
        "mylabel2::myvalue"
        not in helmbundle["spec"]["releases"][1]["values"]["overrides"][
            "openvswitch-db"
        ]["labels"]
    )
    mock_log.assert_not_called()


def test_spec_hash():
    obj1 = """{
"spec": {
  "foo": {
    "bar": "baz",
    "eggs": {
        "parrots": "vikings",
        "ham": "spam"
        }
    },
  "fools": [1,2]
 }
}
 """
    # change order of keys in spec, change order of keys overall,
    # change values in keys other that spec
    # spec_hash should be the same
    obj2 = """{
"spec": {
  "fools": [1,2],
  "foo": {
    "eggs": {
        "ham": "spam",
        "parrots": "vikings"
        },
    "bar": "baz"
    }
 }
 }
"""
    assert layers.spec_hash(json.loads(obj1)) == layers.spec_hash(
        json.loads(obj2)
    )


def test_merge_list_with_duplicates():
    merger = layers.merger
    l = [
        {
            "conf": {
                "nova": {
                    "DEFAULT": {
                        "passthrough_whitelist": '[{ "devname": "enp5s0f2", "physical_network": "physnet2"}]'
                    }
                }
            },
            "label": {"key": "devname", "values": ["enp5s0f1"]},
        }
    ]
    new_list = merger.merge(l, copy.deepcopy(l))
    assert new_list == l


def test_render_cache_template(
    openstackdeployment_mspec,
    mock_kube_artifacts_configmap,
    mock_kube_get_osdpl,
):
    images = {
        "neutron-db-sync": "neutron:latest",
        "nova-api": "nova:latest",
        "libvirt": "libvirt:latest",
        "openvswitch": "openvswitch:latest",
    }
    cache = layers.render_cache_template(
        openstackdeployment_mspec,
        f"{constants.CACHE_NAME}-0",
        images,
        {"node": "one"},
    )
    with open("tests/fixtures/cache_images.yaml") as f:
        expected = yaml.safe_load(f)
    assert expected == cache
