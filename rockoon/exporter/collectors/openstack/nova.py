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


class OsdplNovaMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_nova"
    _description = "OpenStack Compute service metrics"
    _os_service_types = ["compute"]

    def __init__(self):
        self.hypervisor_resource_classes = [
            "vcpu",
            "disk_gb",
            "memory_mb",
            "pcpu",
        ]
        self.hypervisor_metrics = ["used", "free", "allocation_ratio"]
        self.host_group_types = ["aggregate", "availability_zone"]
        self.host_group_types_labels = {
            "aggregate": ["name"],
            "availability_zone": ["zone"],
        }
        self.cache = {}
        super().__init__()

    @utils.timeit
    def update_cache(self):
        """Upadate cache for some API objects

        Cache only small amount of data from API that we use intensively in
        different places to avoid massive API calls. Should not add resources
        that consume a lot of space like servers.
        """
        self.oc.oc.compute.get("/")
        self.cache["aggregates"] = list(self.oc.oc.compute.aggregates())
        self.cache["availability_zones"] = list(
            self.oc.oc.compute.availability_zones()
        )
        self.cache["hypervisors"] = list(self.oc.oc.compute.hypervisors())
        self.cache["services"] = list(self.oc.oc.compute.services())
        self.cache["resource_providers"] = list(
            self.oc.oc.placement.resource_providers()
        )

    @utils.timeit
    def get_host_resource_provider(self, name):
        for resource_provider in self.cache.get("resource_providers", []):
            if resource_provider["name"] == name:
                return resource_provider

    @utils.timeit
    def get_resource_provider_inventories(self, rp):
        return self.oc.oc.placement.get(
            f"/resource_providers/{rp.id}/inventories"
        ).json()["inventories"]

    @utils.timeit
    def get_resource_provider_usages(self, rp):
        return self.oc.oc.placement.get(
            f"/resource_providers/{rp.id}/usages"
        ).json()["usages"]

    @utils.timeit
    def get_host_availability_zone(self, host):
        for service in self.cache.get("services", []):
            if service["host"] == host:
                return service["availability_zone"]

    @utils.timeit
    def get_availability_zone_hosts(self, zone):
        res = []
        for service in self.cache.get("services", []):
            if (
                service.get("availability_zone", "nova") == zone
                and service.get("binary") == "nova-compute"
            ):
                res.append(service["host"])
        return res

    @utils.timeit
    def get_hosts_placement_metrics(self):
        """Return metrics from placement for hosts

        Takes into account only resource_classes we care about, specified in
        self.hypervisor_resource_classes
        """
        hosts = {}
        for hypervisor in self.cache.get("hypervisors", []):
            host_name = hypervisor["name"].split(".")[0]
            host = {}
            rp = self.get_host_resource_provider(hypervisor["name"])
            usages = self.get_resource_provider_usages(rp)
            inventories = self.get_resource_provider_inventories(rp)
            for k, used in usages.items():
                rc = k.lower()
                if rc not in self.hypervisor_resource_classes:
                    continue
                host[f"{rc}_used"] = used

            for k, inventory in inventories.items():
                rc = k.lower()
                if rc not in self.hypervisor_resource_classes:
                    continue
                host[rc] = inventory["total"] * inventory["allocation_ratio"]
                host[f"{rc}_allocation_ratio"] = inventory["allocation_ratio"]
                host[f"{rc}_free"] = (
                    inventory["total"] - inventory["reserved"]
                ) * inventory["allocation_ratio"] - host[f"{k.lower()}_used"]

            hosts[host_name] = host
        return hosts

    @utils.timeit
    def summ_hosts_metrics(self, host_placement_metrics, hosts):
        res = {}
        for host in hosts:
            if host not in host_placement_metrics:
                continue
            host_metrics = host_placement_metrics[host]
            for metric, value in host_metrics.items():
                if "allocation_ratio" in metric:
                    continue
                res.setdefault(metric, 0)
                res[metric] += value
        return res

    def init_families(self):
        res = {
            "service_state": GaugeMetricFamily(
                f"{self._name}_service_state",
                "Nova compute service state",
                labels=["host", "binary", "zone"],
            ),
            "service_status": GaugeMetricFamily(
                f"{self._name}_service_status",
                "Nova compute service status",
                labels=["host", "binary", "zone"],
            ),
            "instances": GaugeMetricFamily(
                f"{self._name}_instances",
                "Total number of instances",
                labels=[],
            ),
            "error_instances": GaugeMetricFamily(
                f"{self._name}_error_instances",
                "Total number of instances in error state",
                labels=[],
            ),
            "active_instances": GaugeMetricFamily(
                f"{self._name}_active_instances",
                "Total number of instances in active state",
                labels=[],
            ),
            "hypervisor_instances": GaugeMetricFamily(
                f"{self._name}_hypervisor_instances",
                "Total number of instances per hypervisor",
                labels=["host", "zone"],
            ),
            "aggregate_hosts": GaugeMetricFamily(
                f"{self._name}_aggregate_hosts",
                "Total number of compute hosts per host aggregate zone",
                labels=["name"],
            ),
            "host_aggregate_info": InfoMetricFamily(
                f"{self._name}_host_aggregate",
                "Information about host aggregate mapping",
                labels=[],
            ),
            "availability_zone_info": InfoMetricFamily(
                f"{self._name}_availability_zone",
                "Information about nova availability zones",
                labels=[],
            ),
            "availability_zone_hosts": GaugeMetricFamily(
                f"{self._name}_availability_zone_hosts",
                "Total number of compute hosts per availability zone",
                labels=["zone"],
            ),
            "availability_zone_instances": GaugeMetricFamily(
                f"{self._name}_availability_zone_instances",
                "Total number of instances with defined availability zone.",
                labels=["zone"],
            ),
            "aggregate_instances": GaugeMetricFamily(
                f"{self._name}_aggregate_instances",
                "Total number of instances on all compute hosts in host aggregate.",
                labels=["name"],
            ),
        }
        for resource_class in self.hypervisor_resource_classes:
            res[f"hypervisor_{resource_class}"] = GaugeMetricFamily(
                f"{self._name}_hypervisor_{resource_class}",
                f"Total number of total available {resource_class} on hypervisor",
                labels=["host", "zone"],
            )
            res[f"hypervisor_{resource_class}_used"] = GaugeMetricFamily(
                f"{self._name}_hypervisor_{resource_class}_used",
                f"Total number of used {resource_class} on hypervisor",
                labels=["host", "zone"],
            )
            res[f"hypervisor_{resource_class}_free"] = GaugeMetricFamily(
                f"{self._name}_hypervisor_{resource_class}_free",
                f"Total number of free {resource_class} on hypervisor",
                labels=["host", "zone"],
            )
            res[f"hypervisor_{resource_class}_allocation_ratio"] = (
                GaugeMetricFamily(
                    f"{self._name}_hypervisor_{resource_class}_allocation_ratio",
                    f"Total number of {resource_class} allocation_ratio on hypervisor",
                    labels=["host", "zone"],
                )
            )
        for group_type in self.host_group_types:
            labels = self.host_group_types_labels[group_type]
            for resource_class in self.hypervisor_resource_classes:
                res[f"{group_type}_{resource_class}"] = GaugeMetricFamily(
                    f"{self._name}_{group_type}_{resource_class}",
                    f"Total number of total available {resource_class} in {group_type}",
                    labels=labels,
                )
                res[f"{group_type}_{resource_class}_used"] = GaugeMetricFamily(
                    f"{self._name}_{group_type}_{resource_class}_used",
                    f"Total number of used {resource_class} in {group_type}",
                    labels=labels,
                )
                res[f"{group_type}_{resource_class}_free"] = GaugeMetricFamily(
                    f"{self._name}_{group_type}_{resource_class}_free",
                    f"Total number of free {resource_class} in {group_type}",
                    labels=labels,
                )
        return res

    @utils.timeit
    def update_aggregate_samples(self, host_placement_metrics):
        """Update aggregate samples.

        :param host_placement_metrics: Dictionary with placement metadata for hosts.
        """
        aggregate_metrics = {}
        if not self.cache.get("aggregates"):
            for resource_class in self.hypervisor_resource_classes:
                for suffix in ["", "_used", "_free"]:
                    metric_name = f"aggregate_{resource_class}{suffix}"
                    self.set_samples(metric_name, [])

        for aggregate in self.cache.get("aggregates", []):
            metrics = self.summ_hosts_metrics(
                host_placement_metrics, aggregate["hosts"]
            )
            aggregate_metrics[aggregate["name"]] = metrics

        aggregate_metric_samples = {}
        for aggregate_name, metrics in aggregate_metrics.items():
            for metric_name, metric_value in metrics.items():
                aggregate_metric_samples.setdefault(
                    f"aggregate_{metric_name}", []
                )
                aggregate_metric_samples[f"aggregate_{metric_name}"].append(
                    ([aggregate_name], metric_value)
                )

        for metric_name, samples in aggregate_metric_samples.items():
            self.set_samples(metric_name, samples)

    @utils.timeit
    def update_availability_zone_samples(self, host_placement_metrics):
        """Update availability_zone samples.

        :param host_placement_metrics: Dictionary with placement metadata for hosts.
        """
        az_metrics = {}
        for zone in self.cache.get("availability_zones", []):
            hosts = self.get_availability_zone_hosts(zone["name"])
            metrics = self.summ_hosts_metrics(host_placement_metrics, hosts)
            az_metrics[zone["name"]] = metrics

        az_metric_samples = {}
        for zone_name, metrics in az_metrics.items():
            for metric_name, metric_value in metrics.items():
                az_metric_samples.setdefault(
                    f"availability_zone_{metric_name}", []
                )
                az_metric_samples[f"availability_zone_{metric_name}"].append(
                    ([zone_name], metric_value)
                )

        for metric_name, samples in az_metric_samples.items():
            self.set_samples(metric_name, samples)

    @utils.timeit
    def update_availability_zone_info_samples(self):
        availability_zone_info_samples = []
        for zone in self.cache.get("availability_zones", []):
            availability_zone_info_samples.append(
                (
                    [],
                    {
                        "zone": zone["name"],
                    },
                )
            )
        self.set_samples(
            "availability_zone_info", availability_zone_info_samples
        )

    @utils.timeit
    def update_availability_zone_hosts(self):
        availability_zone_hosts_samples = []
        for zone in self.cache.get("availability_zones", []):
            zone_name = zone["name"]
            hosts_number = len(self.get_availability_zone_hosts(zone_name))
            availability_zone_hosts_samples.append(([zone_name], hosts_number))

        self.set_samples(
            "availability_zone_hosts", availability_zone_hosts_samples
        )

    @utils.timeit
    def update_host_aggregate_samples(self):
        host_aggregate_info_samples = []
        host_aggregate_hosts_samples = []
        for aggregate in self.cache.get("aggregates", []):
            hosts = aggregate["hosts"] or []
            hosts_number = len(hosts)
            aggregate_name = aggregate["name"]
            for host in hosts:
                host_aggregate_info_samples.append(
                    (
                        [],
                        {
                            "host": host,
                            "name": aggregate_name,
                        },
                    )
                )
            host_aggregate_hosts_samples.append(
                (
                    [aggregate_name],
                    hosts_number,
                )
            )

        self.set_samples("host_aggregate_info", host_aggregate_info_samples)
        self.set_samples("aggregate_hosts", host_aggregate_hosts_samples)

    @utils.timeit
    def update_hypervisor_samples(self, host_placement_metrics):
        hypervisors_samples = {}
        for resource_class in self.hypervisor_resource_classes:
            hypervisors_samples[f"hypervisor_{resource_class}"] = []
            for metric in self.hypervisor_metrics:
                hypervisors_samples[
                    f"hypervisor_{resource_class}_{metric}"
                ] = []

        for host, host_metrics in host_placement_metrics.items():
            zone = self.get_host_availability_zone(host)
            for metric_name, metric_value in host_metrics.items():
                hypervisors_samples[f"hypervisor_{metric_name}"].append(
                    ([host, zone], metric_value)
                )
        for metric_name, samples in hypervisors_samples.items():
            self.set_samples(metric_name, samples)

    @utils.timeit
    def update_service_samples(self):
        state_samples = []
        status_samples = []
        for service in self.cache.get("services", {}):
            zone = service.get("availability_zone", "nova")
            state_samples.append(
                (
                    [
                        service["host"],
                        service["binary"],
                        zone,
                    ],
                    getattr(constants.ServiceState, service["state"]),
                )
            )
            status_samples.append(
                (
                    [
                        service["host"],
                        service["binary"],
                        zone,
                    ],
                    getattr(constants.ServiceStatus, service["status"]),
                )
            )

        self.set_samples("service_state", state_samples)
        self.set_samples("service_status", status_samples)

    @utils.timeit
    def update_instances_samples(self):
        instances = {"total": 0, "active": 0, "error": 0}
        hypervisor_instances = {}
        availability_zone_instances_total = {}
        for zone in self.cache.get("availability_zones", []):
            availability_zone_instances_total[zone["name"]] = 0
        for instance in self.oc.oc.compute.servers(all_projects=True):
            status = instance["status"].lower()
            host = instance.get("compute_host")
            zone = instance.get("availability_zone")
            instances["total"] += 1
            if status in instances.keys():
                instances[status] += 1
                hypervisor_instances.setdefault(host, {"total": 0})
                hypervisor_instances[host]["total"] += 1
            if zone:
                availability_zone_instances_total.setdefault(zone, 0)
                availability_zone_instances_total[zone] += 1

        self.set_samples("instances", [([], instances["total"])])
        for key in ["error", "active"]:
            self.set_samples(f"{key}_instances", [([], instances[key])])

        availability_zone_instances_samples = []
        for zone, total in availability_zone_instances_total.items():
            availability_zone_instances_samples.append(([zone], total))
        self.set_samples(
            "availability_zone_instances", availability_zone_instances_samples
        )

        hypervisor_instances_samples = []
        for hypervisor in self.cache.get("hypervisors", []):
            host_name = hypervisor["name"].split(".")[0]
            total_instances = hypervisor_instances.get(
                host_name, {"total": 0}
            )["total"]
            hypervisor_instances_samples.append(
                (
                    [
                        host_name,
                        self.get_host_availability_zone(host_name) or "None",
                    ],
                    total_instances,
                )
            )
        self.set_samples("hypervisor_instances", hypervisor_instances_samples)
        return hypervisor_instances

    @utils.timeit
    def update_aggregate_instances(self, hypervisor_instances):
        def sum_hosts_instances(hypervisor_instances, hosts):
            res = 0
            for host in hosts:
                res = (
                    res + hypervisor_instances.get(host, {"total": 0})["total"]
                )
            return res

        aggregate_instances_samples = []
        for aggregate in self.cache.get("aggregates", []):
            ag_name = aggregate["name"]
            ag_hosts = aggregate["hosts"] or []
            aggregate_instances_samples.append(
                (
                    [ag_name],
                    sum_hosts_instances(hypervisor_instances, ag_hosts),
                )
            )
        self.set_samples("aggregate_instances", aggregate_instances_samples)

    @utils.timeit
    def update_samples(self):
        self.update_cache()
        host_placement_metrics = self.get_hosts_placement_metrics()

        self.update_service_samples()
        self.update_hypervisor_samples(host_placement_metrics)
        self.update_host_aggregate_samples()
        self.update_aggregate_samples(host_placement_metrics)
        self.update_availability_zone_samples(host_placement_metrics)
        self.update_availability_zone_info_samples()
        self.update_availability_zone_hosts()
        hypervisor_instances = self.update_instances_samples()
        self.update_aggregate_instances(hypervisor_instances)
