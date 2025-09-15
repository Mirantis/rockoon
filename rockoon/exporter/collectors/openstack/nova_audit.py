#!/usr/bin/env python3
#    Copyright 2024 Mirantis, Inc.
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
import json
import time
from prometheus_client.core import GaugeMetricFamily

from rockoon import kube, utils
from rockoon.exporter import settings
from rockoon.exporter.collectors.openstack import base

LOG = utils.get_logger(__name__)


class OsdplNovaAuditMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_nova_audit"
    _description = "OpenStack Compute audit metrics"
    _os_service_types = ["compute", "placement"]

    def __init__(self):
        super().__init__()

    @property
    def can_collect_data(self):
        if not super().can_collect_data:
            return False
        if not kube.get_configmap("nova-placement-audit-report"):
            LOG.warning("No audit configmap found, cannot collect")
            return False
        return True

    def init_families(self):
        res = {
            "orphaned_allocations": GaugeMetricFamily(
                f"{self._name}_orphaned_allocations",
                "Total number of orphaned allocations on all resource providers",
                labels=[],
            ),
            "resource_provider_orphaned_allocations": GaugeMetricFamily(
                f"{self._name}_resource_provider_orphaned_allocations",
                "Total number of orphaned allocations per resource provider",
                labels=["resource_provider"],
            ),
            "resource_provider_orphaned_resources": GaugeMetricFamily(
                f"{self._name}_resource_provider_orphaned_resources",
                "Total amount of resources consumed by orphaned allocations per resource provider per resource class",
                labels=["resource_provider", "resource_class"],
            ),
        }
        return res

    @utils.timeit
    def get_audit_report(self):
        cm = kube.get_configmap("nova-placement-audit-report", silent=False)
        ts = utils.k8s_timestamp_to_unix(cm.obj["data"]["report_ts"])
        report_age = (time.time() - ts) / 3600
        LOG.debug(
            f"Report timestamp is {ts}, report age is {report_age} hours"
        )
        if report_age > settings.OSCTL_EXPORTER_NOVA_AUDIT_TTL:
            raise ValueError(
                f"Report age {report_age} higher than expected {settings.OSCTL_EXPORTER_NOVA_AUDIT_TTL} hours"
            )
        report = json.loads(cm.obj["data"]["report"])
        return report

    @utils.timeit
    def update_orphaned_allocations_samples(self):
        rp_data = {}
        rp_orph_allocations_samples = []
        rp_orph_resources_samples = []
        orphaned_allocations_total = 0

        report = self.get_audit_report()
        detected = report["orphaned_allocations"]["detected"]
        for rp_uuid, allocations in detected.items():
            rp_data.setdefault(rp_uuid, {"total": 0, "total_resources": {}})
            rp_data[rp_uuid]["total"] = len(allocations)
            for alloc in allocations:
                for rc, amount in alloc["resources"].items():
                    if rp_data[rp_uuid]["total_resources"].get(rc):
                        rp_data[rp_uuid]["total_resources"][rc] += amount
                    else:
                        rp_data[rp_uuid]["total_resources"][rc] = amount
            orphaned_allocations_total += rp_data[rp_uuid]["total"]

        for rp_uuid, data in rp_data.items():
            rp_orph_allocations_samples.append(([rp_uuid], data["total"]))
            for resource_class, value in rp_data[rp_uuid][
                "total_resources"
            ].items():
                rp_orph_resources_samples.append(
                    ([rp_uuid, resource_class], value)
                )

        self.set_samples(
            "orphaned_allocations", [([], orphaned_allocations_total)]
        )
        self.set_samples(
            "resource_provider_orphaned_allocations",
            rp_orph_allocations_samples,
        )
        self.set_samples(
            "resource_provider_orphaned_resources", rp_orph_resources_samples
        )

    @utils.timeit
    def update_samples(self):
        self.update_orphaned_allocations_samples()
