import time
import logging

import unittest

from rockoon import kube
from rockoon.tests.functional import config
from rockoon.tests.functional import base
from rockoon import settings

LOG = logging.getLogger(__name__)
CONF = config.Config()


class BaseFunctionalPortProberTestCase(base.BaseFunctionalTestCase):

    def setUp(self):
        super().setUp()
        if not self.neturon_portprober_enabled:
            raise unittest.SkipTest(
                "Neutron PortProber extension is not enabled."
            )
        self.kube_api = kube.kube_client()

    def get_agent_pod(self, host):
        pods = kube.Pod.objects(self.kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={
                "application": "neutron",
                "component": "neutron-portprober-agent",
            },
        )
        for pod in pods:
            if pod.obj["spec"]["nodeName"] == host:
                return pod

    def get_exporter_url(self, host):
        pod = self.get_agent_pod(host)
        pod_ip = pod.obj["status"]["podIP"]
        return f"http://{pod_ip}:{CONF.PORTPROBER_EXPORTER_PORT}"

    def get_arping_samples_for_port(self, port, metric):
        res = {}
        agents = self.get_agents_hosting_portprober_network(port["network_id"])
        for agent in agents:
            res.setdefault(agent["id"], [])
            exporter_url = self.get_exporter_url(agent["host"])
            agent_metric_families = list(
                self.get_metric_families(exporter_url)
            )
            metric_name = f"portprober_arping_target_{metric}"
            m = self.get_metric(metric_name, agent_metric_families)
            if m:
                samples = self.filter_metric_samples(
                    m, {"mac": port.mac_address}
                )
                res[agent["id"]].extend(samples)
        return res

    def wait_arping_samples_for_port(self, port, timeout, interval):
        start_time = time.time()
        while True:
            agent_samples = self.get_arping_samples_for_port(port, "success")
            if len(
                agent_samples.keys()
            ) == CONF.PORTPROBER_AGENTS_PER_NETWORK and all(
                agent_samples.values()
            ):
                return
            time.sleep(interval)
            timed_out = int(time.time()) - start_time
            if timed_out >= timeout:
                message = (
                    f"Timed out waiting samples for port {port.mac_address}"
                )
                LOG.error(message)
                raise TimeoutError(message)

    def _check_arping_metrics_for_network(self, network_id):
        self._test_network_sits_on_agents(
            network_id, expected_number=CONF.PORTPROBER_AGENTS_PER_NETWORK
        )
        agents = self.get_agents_hosting_portprober_network(network_id)
        for agent in agents:
            exporter_url = self.get_exporter_url(agent["host"])
            agent_metric_families = list(
                self.get_metric_families(exporter_url)
            )
            for metric in ["failure", "success", "total"]:
                metric_name = f"portprober_arping_target_{metric}"
                m = self.get_metric(metric_name, agent_metric_families)
                self.assertIsNotNone(
                    m, f"The metric {metric_name} should not be None."
                )
                self.assertTrue(
                    len(m.samples) > 0,
                    f"The metric {metric_name} should have samples.",
                )
