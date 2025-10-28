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

from unittest import mock
import copy
import openstack

from keystoneauth1 import exceptions as ksa_exceptions
import kopf
import pytest

from rockoon import openstack_utils
from rockoon import kube


NODE_OBJ = {
    "apiVersion": "v1",
    "kind": "Node",
    "metadata": {
        "name": "host1",
        "uid": "42",
        "labels": {
            "openstack-compute-node": "enabled",
        },
    },
}


def _get_node(host="host1", role="compute"):
    node_obj = copy.deepcopy(NODE_OBJ)
    node_obj["metadata"]["name"] = host
    if role == "compute":
        node_obj["metadata"]["labels"] = {"openstack-compute-node": "enabled"}
    if role == "control":
        node_obj["metadata"]["labels"] = {"openstack-control-plane": "enabled"}
    return node_obj


def test_openstack_client_no_creds(mocker, openstack_connect):
    openstack_utils.OpenStackClientManager()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_called_once()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down_exception_unknown(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_client_manager.side_effect = Exception("Boom")
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down_exception_no_masakari(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_client_manager.side_effect = ksa_exceptions.EndpointNotFound(
        "Not found"
    )
    openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down_host_not_in_segment_400(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_client_manager.side_effect = openstack.exceptions.HttpException(
        f"Host with name {node.name} could not be found.", http_status=400
    )
    openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down_host_not_in_segment_500(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_client_manager.side_effect = openstack.exceptions.HttpException(
        f"Host with name {node.name} could not be found.", http_status=500
    )
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
def test_notify_masakari_host_down_unknown(
    openstack_client_manager,
):
    node = kube.Node(mock.Mock, copy.deepcopy(_get_node()))
    openstack_client_manager.side_effect = Exception("Error")
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.notify_masakari_host_down(node)
    openstack_client_manager.return_value.instance_ha_create_notification.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_ready(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = True
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()
    nwl.return_value.is_active.assert_not_called()
    mock_log.info.assert_called_with(
        f"The node {node.name} is ready. Skip masakari notification"
    )


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_active(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_inactive(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = False
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()
    mock_log.info.assert_called_with(
        f"The nwl for node {node.name} is inctive. Skip masakari notification."
    )


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_active_unschedulable(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = True
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()
    mock_log.info.assert_called_with(
        f"The scheduling is disabled on node {node.name}, this is intentional, skip masakari notification."
    )


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_active_osctl_exception(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    openstack_client_manager.side_effect = Exception()
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_active_compute_up(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    compute_services = [{"state": "up"}, {"state": "down"}]
    openstack_client_manager.return_value.compute_get_services.return_value = (
        compute_services
    )
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_called_once()
    openstack_client_manager.return_value.network_get_agents.assert_not_called()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_active_network_agent_up(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    compute_services = [{"state": "down"}, {"state": "down"}]
    network_agents = [{"alive": True}]
    openstack_client_manager.return_value.compute_get_services.return_value = (
        compute_services
    )
    openstack_client_manager.return_value.network_get_agents.return_value = (
        network_agents
    )
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_called_once()
    openstack_client_manager.return_value.network_get_agents.assert_called_once()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_no_node_ip(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    compute_services = [{"state": "down"}, {"state": "down"}]
    network_agents = []
    openstack_client_manager.return_value.compute_get_services.return_value = (
        compute_services
    )
    openstack_client_manager.return_value.network_get_agents.return_value = (
        network_agents
    )
    node.obj = {
        "status": {"addresses": [{"type": "foo", "address": "1.2.3.4"}]}
    }
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_called_once()
    openstack_client_manager.return_value.network_get_agents.assert_called_once()


@mock.patch("socket.socket")
@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_ssh_okay(
    mock_log, notify_masakari, openstack_client_manager, sock, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    compute_services = [{"state": "down"}, {"state": "down"}]
    network_agents = []
    openstack_client_manager.return_value.compute_get_services.return_value = (
        compute_services
    )
    openstack_client_manager.return_value.network_get_agents.return_value = (
        network_agents
    )
    node.obj = {
        "status": {"addresses": [{"type": "InternalIP", "address": "1.2.3.4"}]}
    }
    sock.connect.return_value = True
    with pytest.raises(kopf.TemporaryError):
        openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_called_once()
    openstack_client_manager.return_value.network_get_agents.assert_called_once()


@mock.patch("socket.socket")
@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_nwl_ssh_failed(
    mock_log, notify_masakari, openstack_client_manager, socket, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    compute_services = [{"state": "down"}, {"state": "down"}]
    network_agents = []
    openstack_client_manager.return_value.compute_get_all_servers.return_value = [
        {"name": "testSrv1"}
    ]
    openstack_client_manager.return_value.compute_get_services.return_value = (
        compute_services
    )
    openstack_client_manager.return_value.network_get_agents.return_value = (
        network_agents
    )
    node.obj = {
        "status": {"addresses": [{"type": "InternalIP", "address": "1.2.3.4"}]}
    }
    socket.return_value.connect.side_effect = Exception("Boom")
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_called_once()
    openstack_client_manager.return_value.compute_get_services.assert_called_once()
    openstack_client_manager.return_value.network_get_agents.assert_called_once()


@mock.patch.object(openstack_utils, "OpenStackClientManager")
@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch("rockoon.openstack_utils.LOG")
def test_handle_masakari_host_down_node_no_servers(
    mock_log, notify_masakari, openstack_client_manager, node, nwl
):
    node.ready = False
    nwl.return_value.is_active.return_value = True
    node.unschedulable = False
    openstack_client_manager.return_value.compute_get_all_servers.return_value = (
        []
    )
    openstack_utils.handle_masakari_host_down(node)
    notify_masakari.assert_not_called()
    openstack_client_manager.return_value.compute_get_services.assert_not_called()
    openstack_client_manager.return_value.network_get_agents.assert_not_called()
