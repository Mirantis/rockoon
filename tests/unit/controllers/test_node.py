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

import datetime
import pytest

from rockoon import openstack_utils
from rockoon.controllers import node as node_controller


@pytest.fixture
def osdpl(mocker):
    osdpl = mocker.patch("rockoon.kube.get_osdpl")
    yield osdpl
    mocker.stopall()


def test_node_status_update_handler_no_osdpl(osdpl, node):
    osdpl.exists.return_value = False
    node.return_value.exists.assert_not_called()


@mock.patch.object(openstack_utils, "handle_masakari_host_down")
def test_node_status_update_handler_node_ready(notify_masakari, osdpl, node):
    osdpl.exists.return_value = True
    node.exists.return_value = True
    node.ready = True
    node.remove_pods.assert_not_called()
    notify_masakari.assert_not_called()


@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch.object(openstack_utils, "handle_masakari_host_down")
def test_node_status_update_handler_not_ready(
    handle_masakari_host_down, notify_masakari_host_down, osdpl, node
):
    osdpl.exists.return_value = True
    node.ready = False
    node.exists.return_value = True
    node.has_role.return_value = True
    last_transition = datetime.datetime.utcnow() - datetime.timedelta(
        seconds=150
    )
    node.obj = {
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "lastTransitionTime": last_transition.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            ]
        }
    }
    node_controller.node_status_update_handler(
        node.name, node.obj, {}, {}, "reason", diff={}
    )
    node.remove_pods.assert_called_once()
    notify_masakari_host_down.assert_not_called()
    handle_masakari_host_down.assert_called_once()


@mock.patch.object(openstack_utils, "notify_masakari_host_down")
@mock.patch.object(openstack_utils, "handle_masakari_host_down")
def test_node_status_update_handler_not_ready_no_role(
    handle_masakari_host_down, notify_masakari_host_down, osdpl, node
):
    osdpl.exists.return_value = True
    node.ready = False
    node.exists.return_value = True
    node.has_role.return_value = False
    last_transition = datetime.datetime.utcnow() - datetime.timedelta(
        seconds=150
    )
    node.obj = {
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "lastTransitionTime": last_transition.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            ]
        }
    }
    node_controller.node_status_update_handler(
        node.name, node.obj, {}, {}, "reason", diff={}
    )
    node.remove_pods.assert_called_once()
    notify_masakari_host_down.assert_not_called()
    handle_masakari_host_down.assert_not_called()
