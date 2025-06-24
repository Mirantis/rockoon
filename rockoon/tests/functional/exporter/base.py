import os
import requests
import time
import logging

from prometheus_client.openmetrics.parser import text_string_to_metric_families

from rockoon import kube
from rockoon.tests.functional import config
from rockoon.tests.functional import base

LOG = logging.getLogger(__name__)
CONF = config.Config()


class PrometheusMixin:

    def get_metric_families(self, exporter_url=None):
        exporter_url = exporter_url or self.exporter_url
        res = requests.get(exporter_url, timeout=60)
        return text_string_to_metric_families(res.text + "# EOF")

    def get_metric(self, name, metric_families=None):
        if metric_families is None:
            metric_families = self.metric_families
        for metric in metric_families:
            if metric.name == name:
                LOG.info(f"Got metric: {metric}")
                return metric

    def filter_metric_samples(self, metric, labels):
        res = []
        if metric is None:
            return res
        for sample in metric.samples:
            for label, value in labels.items():
                if sample.labels.get(label) != value:
                    break
            else:
                res.append(sample)
        return res

    def sum_metric_samples(self, metric):
        res = 0
        for sample in metric.samples:
            res += sample.value
        return res


class BaseFunctionalExporterTestCase(
    base.BaseFunctionalTestCase, PrometheusMixin
):
    known_metrics = {}

    # Dictionary with known metrics for exporter to check.
    #  * that metric is present
    #  * metric labels are set
    #  * metric has at least one sample
    #
    # {'<metric_name>': {"labels": []}}
    # Only metrics that are always present on environment should be added

    def setUp(self):
        super().setUp()
        self.exporter_url = self.get_exporter_url()

    def get_exporter_url(self):
        if os.environ.get("OSDPL_EXPORTER_URL"):
            return os.environ.get("OSDPL_EXPORTER_URL")
        svc_class = kube.get_object_by_kind("Service")
        svc = kube.find(svc_class, "rockoon-exporter", namespace="osh-system")
        internal_ip = svc.obj["spec"]["clusterIPs"][0]
        return f"http://{internal_ip}:9102"

    @property
    def metric_families(self):
        return self.get_metric_families()

    def get_metric_after_refresh(self, metric_name, scrape_collector):
        collector_metrics = self.get_collector_metrics(scrape_collector)
        return self.get_metric(metric_name, collector_metrics)

    def filter_collector_metrics(self, metrics, scrape_collector):
        def is_collector_metric(metric):
            if metric.name.startswith(scrape_collector):
                return True

        return filter(is_collector_metric, metrics)

    def get_collector_metrics(self, scrape_collector):
        current_time = time.time()
        while True:
            all_metrics = list(self.metric_families)
            scrape_collector_metrics = self.get_metric(
                "osdpl_scrape_collector_start_timestamp", all_metrics
            )
            start_time = self.filter_metric_samples(
                scrape_collector_metrics, {"collector": scrape_collector}
            )[0].value
            end_time = self.filter_metric_samples(
                self.get_metric(
                    "osdpl_scrape_collector_end_timestamp", all_metrics
                ),
                {"collector": scrape_collector},
            )[0].value
            if start_time > current_time and end_time > current_time:
                LOG.debug(
                    f"Metrics for collector {scrape_collector} were refreshed in exporter after updates in openstack API."
                )
                return self.filter_collector_metrics(
                    all_metrics, scrape_collector
                )
            time.sleep(CONF.METRIC_INTERVAL_TIMEOUT)
            timed_out = (
                int(time.time()) - int(current_time) >= CONF.METRIC_TIMEOUT
            )
            message = f"Metrics for collector {scrape_collector} were not updated after timeout {CONF.METRIC_TIMEOUT}."
            if timed_out:
                logging.error(message)
                raise TimeoutError(message)

    def get_resource_provider_inventories(self, hypervisor):
        return self.ocm.oc.placement.get(
            f"/resource_providers/{hypervisor}/inventories"
        ).json()["inventories"]

    def get_allocation_ratio(self, hypervisor, inventory):
        inventories = self.get_resource_provider_inventories(hypervisor)
        return inventories[inventory]["allocation_ratio"]

    def test_known_metrics_present_and_not_none(self):
        all_metrics = list(self.metric_families)
        for metric_name in self.known_metrics.keys():
            metric = self.get_metric(metric_name, all_metrics)
            self.assertIsNotNone(
                metric, f"The metric {metric_name} should not be None."
            )
            self.assertTrue(
                len(metric.samples) > 0,
                f"The metric {metric_name} should have samples.",
            )

    def test_known_metrics_labels(self):
        all_metrics = list(self.metric_families)
        for metric_name, data in self.known_metrics.items():
            metric = self.get_metric(metric_name, all_metrics)
            self.assertIsNotNone(metric)
            for sample in metric.samples:
                for label in data.get("labels", []):
                    self.assertTrue(
                        label in sample.labels,
                        f"Label {label} is not found in metric {metric_name} labels.",
                    )

    def get_pool_by_volume(self, volume):
        host = self.ocm.oc.get_volume(volume["id"])["host"]
        if volume.volume_type == "lvm":
            pool = [
                pool
                for pool in list(self.ocm.oc.volume.backend_pools())
                if pool["name"] == host
            ][0]

        else:
            pool = [
                pool
                for pool in list(self.ocm.oc.volume.backend_pools())
                if pool["name"].split("#")[1] == host.split("#")[1]
            ][0]
        return pool

    def assert_metric_value(self, metric_name, expected_value, error_message):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
        totype = type(expected_value)
        self.assertEqual(
            totype(metric.samples[0].value),
            expected_value,
            f"{error_message}: metric '{metric_name}'"
            f" does not match expected value ({expected_value})",
        )
