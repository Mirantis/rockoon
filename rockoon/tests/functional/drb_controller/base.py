import logging
import unittest
import time
import requests
import pykube

from rockoon import kube
from rockoon.tests.functional import config
from rockoon.tests.functional import base
from rockoon.tests.functional import data_utils

LOG = logging.getLogger(__name__)
CONF = config.Config()


class DRBConfig(pykube.objects.NamespacedAPIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "DRBConfig"
    endpoint = "drbconfigs"


class BaseFunctionalDRBControllerTestCase(
    base.BaseFunctionalTestCase, DRBConfig
):

    CPU_LOAD_SCRIPT = """#!/bin/sh -x
echo "start load on all CPU"
for i in $( seq "$(grep -c ^processor /proc/cpuinfo)" ); do cat /dev/urandom >> /dev/null 2>&1 & done"""

    EXCLUDE_TAG = "lcm.mirantis.com:no-drb"
    INCLUDE_TAG = "lcm.mirantis.com:drb"

    STACKLIGHT_DEFAULT_NODE_METRIC = "node_load5"
    STACKLIGHT_QUERY_ON_ALL_COMPUTE = (
        "on(node) "
        "label_replace("
        'kube_node_labels{label_openstack_compute_node="enabled"}, '
        '"node", "$1", "node", "(.*)")'
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.kube_api = kube.kube_client()
        if not cls.is_drb_controller_enabled():
            raise unittest.SkipTest("DRB Controller is not deployed")

        cls.hosts = list(cls.ocm.oc.compute.hypervisors())
        cls.flavor = cls.flavor_create(vcpus=4)

    def _check_instance_status(self, server, host):
        server = self.ocm.oc.compute.get_server(server.id)
        self.assertEqual(
            server["status"],
            "ACTIVE",
            f"Server {server.id} has status {server.status}, expect ACTIVE status",
        )
        self.assertEqual(
            server["compute_host"],
            host,
            f"Server {server.id} has migrated to another host {server['compute_host']}",
        )

    @classmethod
    def is_drb_controller_enabled(cls):
        for obj in list(
            kube.pykube.CustomResourceDefinition.objects(cls.kube_api).filter(
                namespace=kube.pykube.all
            )
        ):
            if DRBConfig.endpoint in obj.name:
                return True

    @classmethod
    def get_resource_provider_inventories(cls, hypervisor):
        return cls.ocm.oc.placement.get(
            f"/resource_providers/{hypervisor}/inventories"
        ).json()["inventories"]

    def create_drb_config(
        self,
        # get threshold for initial host (current load %  + 10)
        load_threshold,
        name=data_utils.rand_name(postfix="drb-config"),
        namespace=CONF.DRB_CONFIG_NAMESPACE,
        reconcile_interval=300,
        migrate_any=True,
        hosts=[],
        collector_name="stacklight",
        scheduler_name="vm-optimize",
        actuator_name="os-live-migration",
    ):
        # Define the DRBConfig resource dictionary
        drb_config_dict = {
            "apiVersion": "lcm.mirantis.com/v1alpha1",
            "kind": "DRBConfig",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "reconcileInterval": reconcile_interval,
                "migrateAny": migrate_any,
                "hosts": hosts,
                "collector": {"name": collector_name},
                "scheduler": {
                    "name": scheduler_name,
                    "load_threshold": load_threshold,
                },
                "actuator": {"name": actuator_name},
            },
        }
        DRBConfig(self.kube_api, drb_config_dict).create()
        self.addCleanup(self.delete_drb_config, drb_config_dict)

    def delete_drb_config(self, drb_config):
        DRBConfig(self.kube_api, drb_config).delete()
        timeout = 300
        start_time = time.time()
        while True:
            if not DRBConfig.objects(self.kube_api).filter(
                namespace=CONF.DRB_CONFIG_NAMESPACE
            ):
                return
            time.sleep(30)
            timed_out = int(time.time()) - start_time
            if timed_out >= timeout:
                message = (
                    f"DRB Config has not be deleted "
                    f"within the required time {timeout}"
                )
                LOG.error(message)
                raise TimeoutError(message)

    def get_prometheus_datasource_uid(self):
        response = requests.get(
            CONF.STACKLIGHT_GRAFANA_HOST + "/api/datasources/name/prometheus"
        ).json()
        return response["uid"]

    def get_node_load5_metrics(self, host_name):
        prometheus_datasource_uid = self.get_prometheus_datasource_uid()
        query = [
            {
                "datasource": {"uid": prometheus_datasource_uid},
                "expr": f"sum(node_load5{{node=~'{host_name}'}}) by (node) / sum(machine_cpu_cores{{node=~'{host_name}'}}) by (node) * 100",
                "instant": True,
                "range": False,
                "refId": "nodes_load",
            }
        ]
        data = {"queries": query, "to": "now", "from": "now-1h"}
        for attempt in range(CONF.GRAFANA_MAX_RETRIES):
            response = requests.post(
                CONF.STACKLIGHT_GRAFANA_HOST + "/api/ds/query", json=data
            ).json()
            node_load = response["results"]["nodes_load"]
            if len(node_load["frames"]) == 1 and not (
                node_load["frames"][0]["data"]["values"]
            ):
                LOG.debug(
                    f"Node load metrics for host {host_name} are not available. "
                    f"Sleep for {CONF.GRAFANA_RETRY_INTERVAL} seconds and retry"
                )
                time.sleep(CONF.GRAFANA_RETRY_INTERVAL)
                continue
            else:
                node_load_normalized = node_load["frames"][0]["data"][
                    "values"
                ][1][0]
                LOG.debug(
                    f"Host {host_name} has load - {node_load_normalized}"
                )
                return node_load_normalized
        return None

    def get_node_loads(self):
        hosts_load = {}
        for host in self.hosts:
            host_name = host.name.split(".")[0]
            node_load_normalized = self.get_node_load5_metrics(host_name)
            if not node_load_normalized:
                message = f"Can't make a decision about node loads because node load metrics for host {host_name} are not available"
                LOG.error(message)
                raise Exception(message)
            hosts_load[host_name] = node_load_normalized
        return hosts_load

    def wait_for_nodes_load_stabilization(self):
        start_time = time.time()
        timeout = CONF.NODE_LOAD_STABILIZATION_TIMEOUT
        while True:
            hosts_load = self.get_node_loads()
            first_host = self.hosts[0].name.split(".")[0]
            second_host = self.hosts[1].name.split(".")[0]
            abs_load_diff = abs(
                hosts_load[first_host] - hosts_load[second_host]
            )
            if (
                all(
                    value <= CONF.STABLE_NODE_LOAD
                    for value in hosts_load.values()
                )
                and abs_load_diff <= CONF.NODE_LOAD_ABS_DIFFERENCE
            ):
                LOG.debug(
                    f"All nodes have load less than {CONF.STABLE_NODE_LOAD} "
                    f"and absolute difference between load host {first_host} "
                    f"and load host {second_host} is {abs_load_diff}"
                )
                return
            LOG.debug("Sleep for 200 sec")
            time.sleep(200)
            timed_out = int(time.time()) - start_time
            if timed_out >= timeout:
                message = f"All nodes don't achieve loads less than {CONF.STABLE_NODE_LOAD} or "
                f"absolute difference between host's load is greater than {CONF.NODE_LOAD_ABS_DIFFERENCE}: "
                f"Host {first_host} has load {hosts_load[first_host]}."
                f"Host {second_host} has load {hosts_load[second_host]}."
                LOG.error(message)
                raise TimeoutError(message)
