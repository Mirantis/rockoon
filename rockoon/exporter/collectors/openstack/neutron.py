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


class OsdplNeutronMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_neutron"
    _description = "OpenStack Networking service metrics"
    _os_service_types = ["network"]
    port_statuses = ["down", "error", "active"]

    @property
    def is_tungstenfabric_enabled(self):
        return self.osdpl.mspec["preset"] == "compute-tf"

    @utils.timeit
    def init_families(self):
        res = {
            "networks": GaugeMetricFamily(
                f"{self._name}_networks",
                "Number of neutron networks in environment",
                labels=[],
            ),
            "subnets": GaugeMetricFamily(
                f"{self._name}_subnets",
                "Number of neutron subnets in environment",
                labels=[],
            ),
            "ports": GaugeMetricFamily(
                f"{self._name}_ports",
                "Number of neutron ports in environment",
                labels=[],
            ),
            "routers": GaugeMetricFamily(
                f"{self._name}_routers",
                "Number of neutron routers in environment",
                labels=[],
            ),
            "floating_ips": GaugeMetricFamily(
                f"{self._name}_floating_ips",
                "Number of neutron floating ips in environment",
                labels=["state"],
            ),
            "agent_state": GaugeMetricFamily(
                f"{self._name}_agent_state",
                "State of neutron agent in environment",
                labels=["host", "binary", "zone"],
            ),
            "agent_status": GaugeMetricFamily(
                f"{self._name}_agent_status",
                "Administrative status of neutron agent in environment",
                labels=["host", "binary", "zone"],
            ),
            "availability_zone_info": InfoMetricFamily(
                f"{self._name}_availability_zone",
                "Information about neutron availability zones",
                labels=[],
            ),
            "zone_routers": GaugeMetricFamily(
                f"{self._name}_zone_routers",
                "State of neutron routers in specific zone in environment",
                labels=["zone"],
            ),
            "network_total_ips": GaugeMetricFamily(
                f"{self._name}_network_total_ips",
                "Total number of available IP addresses in the network",
                labels=["network_name", "network_id"],
            ),
            "network_free_ips": GaugeMetricFamily(
                f"{self._name}_network_free_ips",
                "Number of non-allocated IP addresses in the network",
                labels=["network_name", "network_id"],
            ),
            "subnet_total_ips": GaugeMetricFamily(
                f"{self._name}_subnet_total_ips",
                "Total number of available IP addresses in the subnet",
                labels=[
                    "network_name",
                    "network_id",
                    "subnet_name",
                    "subnet_id",
                ],
            ),
            "subnet_free_ips": GaugeMetricFamily(
                f"{self._name}_subnet_free_ips",
                "Number of non-allocated IP addresses in the subnet",
                labels=[
                    "network_name",
                    "network_id",
                    "subnet_name",
                    "subnet_id",
                ],
            ),
        }
        for port_status in self.port_statuses:
            res[f"{port_status}_ports"] = GaugeMetricFamily(
                f"{self._name}_{port_status}_ports",
                f"Number of neutron ports in the {port_status.upper()} status in environment",
                labels=[],
            )
        return res

    @utils.timeit
    def update_samples(self):
        for resource in ["networks", "subnets"]:
            total = len(list(getattr(self.oc.oc.network, resource)()))
            self.set_samples(resource, [([], total)])

        routers_total = 0
        zone_routers = {}
        for router in self.oc.oc.network.routers() or []:
            routers_total += 1
            # NOTE(vsaienko): TF return None instead of []
            router_zones = router.get("availability_zones") or []
            for zone in router_zones:
                zone_routers.setdefault(zone, 0)
                zone_routers[zone] += 1

        zone_routers_samples = []
        for zone, routers in zone_routers.items():
            zone_routers_samples.append(([zone], zone_routers[zone]))
        self.set_samples("zone_routers", zone_routers_samples)
        self.set_samples("routers", [([], routers_total)])

        ports = {"total": 0}
        for port_status in self.port_statuses:
            ports[port_status] = 0
        for port in self.oc.oc.network.ports():
            ports["total"] += 1
            port_status = port["status"].lower()
            if port_status in ports.keys():
                ports[port_status] += 1

        self.set_samples("ports", [([], ports["total"])])
        for port_status in self.port_statuses:
            self.set_samples(
                f"{port_status}_ports",
                [([], ports[port_status])],
            )

        floating_ips_associated = 0
        floating_ips_not_associated = 0
        for fip in self.oc.oc.network.ips():
            if fip.get("port_id") is not None:
                floating_ips_associated += 1
            else:
                floating_ips_not_associated += 1

        self.set_samples(
            "floating_ips",
            [
                (["associated"], floating_ips_associated),
                (
                    ["not_associated"],
                    floating_ips_not_associated,
                ),
            ],
        )

        agent_samples = {"is_alive": [], "is_admin_state_up": []}
        for agent in self.oc.network_get_agents():
            az = agent["availability_zone"] or "nova"
            for field in agent_samples.keys():
                if field in agent.to_dict():
                    agent_samples[field].append(
                        (
                            [
                                agent["host"],
                                agent["binary"],
                                az,
                            ],
                            int(agent[field]),
                        )
                    )
        self.set_samples("agent_state", agent_samples["is_alive"])
        self.set_samples("agent_status", agent_samples["is_admin_state_up"])

        availability_zone_info_samples = []
        for zone in self.oc.network_get_availability_zones():
            availability_zone_info_samples.append(
                (
                    [],
                    {
                        "zone": zone["name"],
                        "resource": zone["resource"],
                    },
                )
            )
        self.set_samples(
            "availability_zone_info", availability_zone_info_samples
        )

        # Tungsten Fabric doesn't have network IP availability extension
        if not self.is_tungstenfabric_enabled:
            network_total_ips_samples = []
            network_free_ips_samples = []
            subnet_total_ips_samples = []
            subnet_free_ips_samples = []
            collect_metrics_tag = constants.NEUTRON_NETWORK_IP_METRICS_TAG
            eligible_networks = list(
                self.oc.oc.network.networks(
                    is_router_external=True,
                    provider_network_type=["vlan", "flat"],
                )
            )
            eligible_networks.extend(
                list(self.oc.oc.network.networks(tags=[collect_metrics_tag]))
            )
            unique_networks = {
                network.id: network for network in eligible_networks
            }
            eligible_networks = list(unique_networks.values())
            eligible_networks_ids = {
                network.id for network in eligible_networks
            }
            for network in eligible_networks:
                network_id = network["id"]
                network_name = network.get("name") or "None"
                ip_availability = (
                    self.oc.oc.network.get_network_ip_availability(network_id)
                )
                network_total_ips = ip_availability["total_ips"]
                network_used_ips = ip_availability["used_ips"]
                network_free_ips = network_total_ips - network_used_ips
                network_total_ips_samples.append(
                    (
                        [network_name, network_id],
                        network_total_ips,
                    )
                )
                network_free_ips_samples.append(
                    (
                        [network_name, network_id],
                        network_free_ips,
                    )
                )
                for subnet in (
                    ip_availability.get("subnet_ip_availability") or []
                ):
                    subnet_name = subnet.get("subnet_name") or "None"
                    subnet_id = subnet["subnet_id"]
                    subnet_total_ips = subnet["total_ips"]
                    subnet_used_ips = subnet["used_ips"]
                    subnet_free_ips = subnet_total_ips - subnet_used_ips
                    subnet_total_ips_samples.append(
                        (
                            [network_name, network_id, subnet_name, subnet_id],
                            subnet_total_ips,
                        )
                    )
                    subnet_free_ips_samples.append(
                        (
                            [network_name, network_id, subnet_name, subnet_id],
                            subnet_free_ips,
                        )
                    )
            self.set_samples("network_total_ips", network_total_ips_samples)
            self.set_samples("network_free_ips", network_free_ips_samples)

            eligible_subnets = list(
                self.oc.oc.network.subnets(tags=[collect_metrics_tag])
            )
            for subnet in eligible_subnets:
                subnet_id = subnet["id"]
                subnet_name = subnet.get("name") or "None"
                network_id = subnet["network_id"]
                if network_id in eligible_networks_ids:
                    # Subnet metrics are already collected with network metrics
                    continue
                network = self.oc.oc.network.get_network(network_id)
                network_name = network.get("name") or "None"
                ip_availability = (
                    self.oc.oc.network.get_network_ip_availability(network_id)
                )
                for subnet_ip_availability in (
                    ip_availability.get("subnet_ip_availability") or []
                ):
                    if subnet_id == subnet_ip_availability["subnet_id"]:
                        subnet_total_ips = subnet_ip_availability["total_ips"]
                        subnet_used_ips = subnet_ip_availability["used_ips"]
                        subnet_free_ips = subnet_total_ips - subnet_used_ips
                        subnet_total_ips_samples.append(
                            (
                                [
                                    network_name,
                                    network_id,
                                    subnet_name,
                                    subnet_id,
                                ],
                                subnet_total_ips,
                            )
                        )
                        subnet_free_ips_samples.append(
                            (
                                [
                                    network_name,
                                    network_id,
                                    subnet_name,
                                    subnet_id,
                                ],
                                subnet_free_ips,
                            )
                        )
                        break
            self.set_samples("subnet_total_ips", subnet_total_ips_samples)
            self.set_samples("subnet_free_ips", subnet_free_ips_samples)
