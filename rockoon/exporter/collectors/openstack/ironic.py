#!/usr/bin/env python3
#    Copyright 2023 Mirantis, Inc.
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

from prometheus_client.core import GaugeMetricFamily, InfoMetricFamily

from rockoon import utils
from rockoon.exporter.collectors.openstack import base
from rockoon.exporter import constants


LOG = utils.get_logger(__name__)


class OsdplIronicMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_ironic"
    _description = "OpenStack Baremetal service metrics"
    _os_service_types = ["baremetal"]
    _osdpl_service_name = "baremetal"

    @utils.timeit
    def init_families(self):
        return {
            "nodes": GaugeMetricFamily(
                f"{self._name}_nodes",
                "The number of baremetal nodes",
                labels=[],
            ),
            "node_info": InfoMetricFamily(
                f"{self._name}_node",
                "The baremetal node info",
                labels=[],
            ),
            "node_maintenance": GaugeMetricFamily(
                f"{self._name}_node_maintenance",
                "Maintenance status of the baremetal node",
                labels=["uuid", "name"],
            ),
            "node_provision_state": GaugeMetricFamily(
                f"{self._name}_node_provision_state",
                "Provision state of the baremetal node",
                labels=["uuid", "name"],
            ),
        }

    @utils.timeit
    def get_node_provision_state_metric_value(self, provision_state):
        return constants.BAREMETAL_NODE_PROVISION_STATE.get(provision_state, 0)

    @utils.timeit
    def update_samples(self):

        nodes = list(self.oc.baremetal_get_nodes())
        nodes_total = len(nodes)
        self.set_samples("nodes", [([], nodes_total)])

        baremetal_node_info_samples = []
        for node in nodes:
            baremetal_node_info_samples.append(
                (
                    [],
                    {
                        "uuid": node["uuid"],
                        "name": node["name"] or "None",
                    },
                )
            )
        self.set_samples(
            "node_info",
            baremetal_node_info_samples,
        )

        baremetal_node_maintenance_samples = []
        for node in nodes:
            baremetal_node_maintenance_samples.append(
                (
                    [
                        node["uuid"],
                        node["name"] or "None",
                    ],
                    int(node["maintenance"]),
                )
            )
        self.set_samples(
            "node_maintenance",
            baremetal_node_maintenance_samples,
        )

        baremetal_node_provision_state_samples = []
        for node in nodes:
            baremetal_node_provision_state_samples.append(
                (
                    [
                        node["uuid"],
                        node["name"] or "None",
                    ],
                    self.get_node_provision_state_metric_value(
                        node["provision_state"]
                    ),
                )
            )
        self.set_samples(
            "node_provision_state",
            baremetal_node_provision_state_samples,
        )
