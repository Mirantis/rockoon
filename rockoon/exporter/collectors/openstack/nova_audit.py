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
import re
import json
from prometheus_client.core import GaugeMetricFamily

from rockoon import kube, utils
from rockoon.exporter.collectors.openstack import base

LOG = utils.get_logger(__name__)


class OsdplNovaAuditMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_nova_audit"
    _description = "OpenStack Compute audit metrics"
    _os_service_types = ["compute", "placement"]

    def __init__(self):
        self.cache = {}
        super().__init__()

    @utils.timeit
    def update_cache(self):
        cronjob = self.get_audit_cronjob()
        if cronjob.obj["spec"]["suspend"]:
            raise ValueError("Audit cronjob is suspended, cannot get report")
        last_job_id = self.cache.get("nova-placement-audit", {}).get(
            "job_id", ""
        )
        job = cronjob.get_latest_job(status="completed")
        job_id = f"{job.name}-{job.start_time}"
        # This method is running after can_collect_data, so there should
        # be existing cronjobs with some completed jobs
        if last_job_id == job_id:
            return
        LOG.info("Updating Nova Placement Audit cache")
        report = self.get_audit_report(job)
        self.cache["nova-placement-audit"] = {
            "report": report,
            "job_id": job_id,
        }

    def get_audit_cronjob(self, silent=False):
        return kube.find(
            kube.CronJob,
            "nova-placement-audit",
            namespace=self.osdpl.namespace,
            silent=silent,
        )

    @property
    def can_collect_data(self):
        if not super().can_collect_data:
            return False
        cronjob = self.get_audit_cronjob(silent=True)
        if not cronjob:
            LOG.warning("No audit cronjob found, cannot collect")
            return False
        if not cronjob.get_latest_job(status="completed"):
            LOG.warning("No completed audit cronjob found, cannot collect")
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
    def get_audit_report(self, job):
        if not job.ready:
            raise ValueError(f"Job {job} is not ready, cannot get report")
        for pod in job.pods:
            if pod.obj["status"].get("phase") == "Succeeded":
                logs = pod.logs(container="placement-audit-report")
                break
        report_match = re.search(r"(\{.*\})", logs)
        if not report_match:
            LOG.debug(f"Report not found in logs {logs}")
            raise ValueError("Cannot get audit report")
        return json.loads(report_match[1])

    @utils.timeit
    def update_orphaned_allocations_samples(self):
        rp_data = {}
        rp_orph_allocations_samples = []
        rp_orph_resources_samples = []
        orphaned_allocations_total = 0

        report = self.cache["nova-placement-audit"]["report"]
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
        self.update_cache()
        self.update_orphaned_allocations_samples()
