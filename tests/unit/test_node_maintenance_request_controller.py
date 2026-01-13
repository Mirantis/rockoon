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

import kopf
import pytest

from rockoon.controllers import (
    maintenance as maintenance_controller,
)
from rockoon import services
from rockoon import maintenance
from rockoon import kube


@pytest.fixture
def nova_registry_service(mocker):
    mock_service_class = mock.Mock()
    mock_service_class.return_value = mock.Mock()
    mocker.patch(
        "rockoon.services.ORDERED_SERVICES",
        [("compute", mock_service_class)],
    )
    methods = [
        "process_nmr",
        "delete_nmr",
        "prepare_node_after_reboot",
        "add_node_to_scheduling",
        "remove_node_from_scheduling",
        "prepare_node_for_reboot",
        "process_ndr",
        "cleanup_metadata",
        "cleanup_persistent_data",
        "is_node_locked",
        "can_handle_nmr",
    ]
    for attr in methods:
        setattr(mock_service_class.return_value, attr, mock.Mock())
    yield mock_service_class
    mocker.stopall()


@pytest.fixture
def neutron_registry_service(mocker):
    mock_service_class = mock.Mock()
    mock_service_class.return_value = mock.Mock()
    mocker.patch(
        "rockoon.services.ORDERED_SERVICES",
        [("networking", mock_service_class)],
    )
    methods = [
        "prepare_node_after_reboot",
        "cleanup_metadata",
        "cleanup_persistent_data",
        "is_node_locked",
    ]
    for attr in methods:
        setattr(mock_service_class.return_value, attr, mock.Mock())
    yield mock_service_class
    mocker.stopall()


@pytest.fixture
def osdpl(mocker):
    osdpl = mocker.patch("rockoon.kube.get_osdpl")
    osdpl.return_value.mspec = {"openstack_version": "antelope"}
    yield osdpl
    mocker.stopall()


def get_maintenance_locks(controller, gateway, compute):
    return {
        "controller": [0] * controller,
        "gateway": [0] * gateway,
        "compute": [0] * compute,
    }


def test_nmr_change_not_required_for_node(
    mocker, nova_registry_service, safe_node
):
    node = safe_node
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = False
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    node.ready = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_change_handler(
        nmr, diff=()
    )
    nwl.required_for_node.assert_called_once()
    nwl.present.assert_not_called()
    nwl.is_maintenance.assert_not_called()
    nwl.is_active.assert_not_called()
    nwl.set_state_inactive.assert_not_called()


def test_nmr_change_required_for_node_not_maintenance_0_active_lock(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = False
    nwl.can_handle_nmr.return_value = True

    osdpl.exists.return_value = True

    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    nova_registry_service.return_value.maintenance_api = True
    nova_registry_service.return_value.can_handle_nmr.return_value = True

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [("compute", nova_registry_service)],
    )

    node.ready = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_change_handler(
        nmr, diff=()
    )
    nwl.required_for_node.assert_called_once()
    nwl.present.assert_called_once()
    nwl.acquire_internal_lock.assert_called_once()
    nwl.is_active.assert_called_once()
    nwl.set_state_inactive.assert_called_once()


def test_nmr_change_required_for_node_not_maintenance_0_active_lock_service_rejected(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = False
    nwl.can_handle_nmr.return_value = True

    osdpl.exists.return_value = True

    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    nova_registry_service.return_value.maintenance_api = True
    nova_registry_service.return_value.can_handle_nmr.return_value = True

    neutron_registry_service = mock.Mock()
    neutron_registry_service.return_value = mock.Mock()
    neutron_registry_service.return_value.maintenance_api = True
    neutron_registry_service.return_value.can_handle_nmr.return_value = False

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [
            ("compute", nova_registry_service),
            ("network", neutron_registry_service),
        ],
    )

    node.ready = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    with pytest.raises(kopf.TemporaryError):
        maintenance_controller.node_maintenance_request_change_handler(
            nmr, diff=()
        )
    nwl.required_for_node.assert_called_once()
    nwl.present.assert_called_once()
    nwl.acquire_internal_lock.assert_called_once()
    nwl.is_active.assert_called_once()
    nwl.set_state_inactive.assert_not_called()


def test_nmr_change_required_for_node_not_maintenance_1_active_lock(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = False
    nwl.acquire_internal_lock.side_effect = kopf.TemporaryError("BOOM")
    nwl.can_handle_nmr.return_value = False

    osdpl.exists.return_value = True

    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    node.ready = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    with pytest.raises(kopf.TemporaryError):
        maintenance_controller.node_maintenance_request_change_handler(
            nmr, diff=()
        )
    nwl.required_for_node.assert_called_once()
    nwl.present.assert_called_once()
    nwl.acquire_internal_lock.assert_called_once()
    nwl.is_active.assert_not_called()
    nwl.set_state_inactive.assert_not_called()


def test_nmr_change_required_for_node_maintenance_1_active_lock(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    nwl.can_handle_nmr.return_value = False

    osdpl.exists.return_value = True

    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    node.ready = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_change_handler(
        nmr, diff=()
    )
    nova_registry_service.return_value.process_nmr.assert_called_once()
    nwl.required_for_node.assert_called_once()
    nwl.present.assert_called_once()
    nwl.acquire_internal_lock.assert_called_once()
    nwl.is_active.assert_called_once()
    nwl.set_state_inactive.assert_called_once()


def test_nmr_delete_stop_not_required_for_node(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = False
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    node.ready = True
    osdpl.exists.return_value = True

    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_delete_handler(nmr)
    nwl.required_for_node.assert_called_once()
    nwl.absent.assert_called_once()
    nwl.is_maintenance.assert_not_called()
    nwl.set_inner_state_inactive.assert_not_called()
    nwl.set_state_active.assert_not_called()


def test_nmr_delete_nwl_not_in_maintenance(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = False
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    osdpl.exists.return_value = True
    node.ready = True

    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_delete_handler(nmr)
    nwl.required_for_node.assert_called_once()
    nwl.absent.assert_not_called()
    nwl.is_maintenance.assert_called()
    nwl.set_inner_state_inactive.assert_called_once()
    nwl.set_state_active.assert_called_once()


def test_nmr_delete_nwl_in_maintenance(
    mocker, nova_registry_service, osdpl, node
):
    nmr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    node.ready = True

    osdpl.exists.return_value = True
    nova_registry_service.return_value.maintenance_api = True
    mocker.patch.object(kube, "find", side_effect=(node,))
    maintenance_controller.node_maintenance_request_delete_handler(nmr)
    nwl.required_for_node.assert_called_once()
    nova_registry_service.return_value.delete_nmr.assert_called_once()
    nwl.absent.assert_not_called()
    nwl.is_maintenance.assert_called()
    nwl.set_inner_state_inactive.assert_called_once()
    nwl.set_state_active.assert_called_once()


def test_ndr_osdpl_not_present(mocker, nova_registry_service, node, osdpl):
    ndr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }

    osdpl.return_value.exists.return_value = False

    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    maintenance_controller.node_deletion_request_change_handler(ndr)
    node.exists.assert_not_called()
    osdpl.return_value.exists.assert_called_once()
    nwl.set_state_inactive.assert_called_once()


def test_ndr_node_not_present(mocker, nova_registry_service, safe_node, osdpl):
    node = safe_node
    ndr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }

    osdpl.return_value.exists.return_value = True
    node.exists.return_value = False
    mocker.patch.object(kube, "find", side_effect=(node,))

    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    maintenance_controller.node_deletion_request_change_handler(ndr)
    node.exists.assert_called_once()
    osdpl.return_value.exists.assert_called_once()
    nwl.set_state_inactive.assert_called_once()


def test_ndr_nova_service(mocker, nova_registry_service, safe_node, osdpl):
    node = safe_node
    ndr = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node"},
    }

    osdpl.return_value.exists.return_value = True
    node.exists.return_value = True
    mocker.patch.object(kube, "find", side_effect=(node,))

    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    nova_registry_service.return_value.maintenance_api = True

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [("compute", nova_registry_service)],
    )

    maintenance_controller.node_deletion_request_change_handler(ndr)
    node.exists.assert_called_once()
    osdpl.return_value.exists.assert_called_once()
    nwl.set_state_inactive.assert_called_once()
    nova_registry_service.return_value.process_ndr.assert_called_once()


def test_nwl_deletion_no_osdpl(
    mocker, nova_registry_service, neutron_registry_service, node, osdpl
):
    nwl_obj = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node", "controllerName": "openstack"},
    }
    osdpl.return_value.exists.return_value = False
    nova_registry_service.return_value.maintenance_api = True

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [
            ("compute", nova_registry_service),
            ("networking", neutron_registry_service),
        ],
    )
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    maintenance_controller.node_workloadlock_request_delete_handler(nwl_obj)
    osdpl.return_value.exists.assert_called_once()
    nova_registry_service.return_value.cleanup_metadata.assert_not_called()
    neutron_registry_service.return_value.cleanup_metadata.assert_not_called()


def test_nwl_deletion_not_our_nwl(
    mocker, nova_registry_service, neutron_registry_service, node, osdpl
):
    nwl_obj = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node", "controllerName": "ceph"},
    }
    osdpl.return_value.exists.return_value = True
    nova_registry_service.return_value.maintenance_api = True

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [
            ("compute", nova_registry_service),
            ("networking", neutron_registry_service),
        ],
    )
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )

    maintenance_controller.node_workloadlock_request_delete_handler(nwl_obj)
    osdpl.return_value.exists.assert_not_called()
    nova_registry_service.return_value.cleanup_metadata.assert_not_called()
    neutron_registry_service.return_value.cleanup_metadata.assert_not_called()


def test_nwl_deletion_node_still_exit(
    mocker, nova_registry_service, node, neutron_registry_service, osdpl
):
    nwl_obj = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node", "controllerName": "openstack"},
    }
    osdpl.return_value.exists.return_value = True
    nova_registry_service.return_value.maintenance_api = True
    node.exists.return_value = True
    mocker.patch.object(kube, "find", side_effect=(node,))

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [
            ("compute", nova_registry_service),
            ("networking", neutron_registry_service),
        ],
    )
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    with pytest.raises(kopf.TemporaryError):
        maintenance_controller.node_workloadlock_request_delete_handler(
            nwl_obj
        )
    osdpl.return_value.exists.assert_called_once()
    nova_registry_service.return_value.cleanup_metadata.assert_not_called()
    neutron_registry_service.return_value.cleanup_metadata.assert_not_called()
    nova_registry_service.return_value.cleanup_persistent_data.assert_not_called()
    neutron_registry_service.return_value.cleanup_persistent_data.assert_not_called()


def test_nwl_deletion_cleanup(
    mocker, nova_registry_service, neutron_registry_service, safe_node, osdpl
):
    node = safe_node
    nwl_obj = {
        "metadata": {"name": "fake-nmr"},
        "spec": {"nodeName": "fake-node", "controllerName": "openstack"},
    }
    osdpl.return_value.exists.return_value = True
    nova_registry_service.return_value.maintenance_api = True
    node.exists.return_value = False
    mocker.patch.object(kube, "find", side_effect=(node,))

    mocker.patch.object(
        services,
        "ORDERED_SERVICES",
        [
            ("compute", nova_registry_service),
            ("networking", neutron_registry_service),
        ],
    )
    nwl = mock.Mock()
    nwl.required_for_node.return_value = True
    nwl.is_maintenance.return_value = True
    mocker.patch.object(
        maintenance.NodeWorkloadLock, "get_by_node", return_value=nwl
    )
    maintenance_controller.node_workloadlock_request_delete_handler(nwl_obj)
    osdpl.return_value.exists.assert_called_once()
    nova_registry_service.return_value.cleanup_metadata.assert_called_once()
    neutron_registry_service.return_value.cleanup_metadata.assert_called_once()
    nova_registry_service.return_value.cleanup_persistent_data.assert_called_once()
    neutron_registry_service.return_value.cleanup_persistent_data.assert_called_once()
