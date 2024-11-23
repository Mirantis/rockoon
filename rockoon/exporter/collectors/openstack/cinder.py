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


from prometheus_client.core import GaugeMetricFamily

from rockoon import utils
from rockoon.exporter.collectors.openstack import base
from rockoon.exporter import constants


LOG = utils.get_logger(__name__)


class OsdplCinderMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_cinder"
    _description = "OpenStack Volume service metrics"
    _os_service_types = [
        "block-storage",
        "volumev3",
        "volumev2",
        "volume",
        "block-store",
    ]

    @utils.timeit
    def init_families(self):
        return {
            "volumes": GaugeMetricFamily(
                f"{self._name}_volumes",
                "Number of cinder volumes in environment",
                labels=[],
            ),
            "volumes_size": GaugeMetricFamily(
                f"{self._name}_volumes_size",
                "Total size of all volumes in bytes",
                labels=[],
            ),
            "snapshots": GaugeMetricFamily(
                f"{self._name}_snapshots",
                "Number of cinder snapshots in environment",
                labels=[],
            ),
            "snapshots_size": GaugeMetricFamily(
                f"{self._name}_snapshots_size",
                "Total size of all snapshots in bytes",
                labels=[],
            ),
            "service_state": GaugeMetricFamily(
                f"{self._name}_service_state",
                "Cinder service state",
                labels=["host", "binary", "zone"],
            ),
            "service_status": GaugeMetricFamily(
                f"{self._name}_service_status",
                "Cinder service status",
                labels=["host", "binary", "zone"],
            ),
            "pool_free_capacity": GaugeMetricFamily(
                f"{self._name}_pool_free_capacity",
                "Free capacity in bytes of cinder backend pools in environment",
                labels=["name"],
            ),
            "pool_total_capacity": GaugeMetricFamily(
                f"{self._name}_pool_total_capacity",
                "Total capacity in bytes of cinder backend pools in environment",
                labels=["name"],
            ),
            "pool_allocated_capacity": GaugeMetricFamily(
                f"{self._name}_pool_allocated_capacity",
                "Allocated capacity in bytes of cinder backend pools in environment",
                labels=["name"],
            ),
            "zone_volumes": GaugeMetricFamily(
                f"{self._name}_zone_volumes",
                "Number of cinder volumes inspecific zone in environment",
                labels=["zone"],
            ),
        }

    @utils.timeit
    def update_samples(self):
        volumes_total = 0
        volumes_size = 0
        snapshots_total = 0
        snapshots_size = 0
        volume_zone_total = {}
        for zone in self.oc.oc.volume.availability_zones():
            volume_zone_total[zone["name"]] = 0

        for volume in self.oc.oc.volume.volumes(all_tenants=True):
            volume_zone = volume.get("availability_zone", "None")
            volumes_total += 1
            # NOTE(vsaienko): the size may be None from API.
            volumes_size += volume.get("size") or 0
            volume_zone_total.setdefault(volume_zone, 0)
            volume_zone_total[volume_zone] += 1
        self.set_samples("volumes", [([], volumes_total)])
        self.set_samples("volumes_size", [([], volumes_size * constants.Gi)])
        zone_volumes_samples = []
        for zone, volumes in volume_zone_total.items():
            zone_volumes_samples.append(([zone], volume_zone_total[zone]))
        self.set_samples("zone_volumes", zone_volumes_samples)
        for snapshot in self.oc.oc.volume.snapshots(all_tenants=True):
            snapshots_total += 1
            snapshots_size += snapshot.get("size") or 0
        self.set_samples("snapshots", [([], snapshots_total)])
        self.set_samples(
            "snapshots_size",
            [([], snapshots_size * constants.Gi)],
        )

        service_state_samples = []
        service_status_samples = []
        for service in self.oc.volume_get_services():
            service_state_samples.append(
                (
                    [
                        service["host"],
                        service["binary"],
                        service["zone"],
                    ],
                    getattr(constants.ServiceState, service["state"]),
                )
            )
            service_status_samples.append(
                (
                    [
                        service["host"],
                        service["binary"],
                        service["zone"],
                    ],
                    getattr(constants.ServiceStatus, service["status"]),
                )
            )
        self.set_samples("service_state", service_state_samples)
        self.set_samples("service_status", service_status_samples)

        pool_free_capacity_samples = []
        pool_total_capacity_samples = []
        pool_allocated_capacity_samples = []
        for backend_pool in self.oc.oc.volume.backend_pools():
            pool_free_capacity_samples.append(
                (
                    [backend_pool["name"]],
                    (
                        backend_pool.get("capabilities", {}).get(
                            "free_capacity_gb"
                        )
                        or 0
                    )
                    * constants.Gi,
                )
            )
            pool_total_capacity_samples.append(
                (
                    [backend_pool["name"]],
                    (
                        backend_pool.get("capabilities", {}).get(
                            "total_capacity_gb"
                        )
                        or 0
                    )
                    * constants.Gi,
                )
            )
            pool_allocated_capacity_samples.append(
                (
                    [backend_pool["name"]],
                    (
                        backend_pool.get("capabilities", {}).get(
                            "allocated_capacity_gb"
                        )
                        or 0
                    )
                    * constants.Gi,
                )
            )

        self.set_samples("pool_free_capacity", pool_free_capacity_samples)
        self.set_samples("pool_total_capacity", pool_total_capacity_samples)
        self.set_samples(
            "pool_allocated_capacity", pool_allocated_capacity_samples
        )
