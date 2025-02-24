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

from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
import requests
from urllib3.exceptions import InsecureRequestWarning

from prometheus_client.core import GaugeMetricFamily

from rockoon import utils
from rockoon.exporter import settings
from rockoon.exporter.collectors.openstack import base


LOG = utils.get_logger(__name__)


def check_endpoint(url, service_type, service_name, headers):
    result = {"success": True}
    try:
        requests.packages.urllib3.disable_warnings(
            category=InsecureRequestWarning
        )
        resp = requests.get(
            url,
            timeout=10,
            verify=settings.OSCTL_EXPORTER_CA_CERT_PATH,
            headers=headers,
        )
        if resp.status_code >= 500:
            LOG.warning(
                f"Got bad responce code {resp.status_code} from {url}."
            )
            result["success"] = False
        result["status"] = (
            [url, service_type, service_name],
            resp.status_code,
        )
        result["latency"] = (
            [url, service_type, service_name],
            resp.elapsed.microseconds,
        )
    except Exception as e:
        LOG.warning(f"Failed to get responce from {url}. Error: {e}")
        result["success"] = False
    return result


class OsdplApiMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_api"
    _description = "OpenStack API endpoints"
    _os_service_types = ["identity"]

    @utils.timeit
    def init_families(self):
        return {
            "status": GaugeMetricFamily(
                f"{self._name}_status",
                "API endpoint connection status",
                labels=["url", "service_type", "service_name"],
            ),
            "latency": GaugeMetricFamily(
                f"{self._name}_latency",
                "API endpoint connection latency microseconds",
                labels=["url", "service_type", "service_name"],
            ),
            "success": GaugeMetricFamily(
                f"{self._name}_success",
                "API endpoint connection success status",
                labels=["url", "service_type", "service_name"],
            ),
        }

    def update_samples(self):
        statuses = []
        latencies = []
        successes = []
        endpoints = list(self.oc.oc.identity.endpoints(interface="public"))
        max_workers = min(20, len(endpoints))
        future_results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for endpoint in endpoints:
                service = self.oc.oc.identity.get_service(endpoint.service_id)
                service_type = self.oc.service_type_manager.get_service_type(
                    service.type
                )
                service_name = service["name"]
                if not service_type:
                    LOG.warning(
                        f"Failed to get service_type for service {service}"
                    )
                    continue
                url = endpoint["url"].split("%")[0]
                token = self.oc.oc.auth_token
                headers = {"X-Auth-Token": token}
                future = executor.submit(
                    check_endpoint,
                    url=url,
                    service_type=service_type,
                    service_name=service_name,
                    headers=headers,
                )
                future_results[(url, service_type, service_name)] = future
        done, not_done = wait(
            future_results.values(),
            return_when=ALL_COMPLETED,
            timeout=30,
        )
        for endpoint_data, future in future_results.items():
            url, service_type, service_name = endpoint_data
            if endpoint_data in not_done:
                successes.append(
                    ([url, service_type, service_name], int(False))
                )
            else:
                result = future.result()
                successes.append(
                    ([url, service_type, service_name], int(result["success"]))
                )
                if "status" in result:
                    statuses.append(result["status"])
                if "latency" in result:
                    latencies.append(result["latency"])

        self.set_samples("status", statuses)
        self.set_samples("latency", latencies)
        self.set_samples("success", successes)
