from parameterized import parameterized

from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import data_utils


class APICollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_api_success": {
            "labels": ["service_name", "service_type", "url"]
        },
        "osdpl_api_latency": {
            "labels": ["service_name", "service_type", "url"]
        },
        "osdpl_api_status": {
            "labels": ["service_name", "service_type", "url"]
        },
    }

    scrape_collector = "osdpl_api"

    def setUp(self):
        super().setUp()

        self.service = None
        self.endpoint = None

    def tearDown(self):
        super().tearDown()

        if self.endpoint:
            self.endpoint_delete(self.endpoint["id"])
        if self.service:
            self.service_delete(self.service["id"])

    def _test_osdpl_api_samples(
        self, metric_name, labels, expected_num, phase
    ):
        metrics = self.get_collector_metrics(self.scrape_collector)
        metric = self.get_metric(metric_name, metrics)
        samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            len(samples),
            expected_num,
            f"{phase}: The service samples is not correct.",
        )

    @parameterized.expand(
        [
            ("osdpl_api_success"),
            ("osdpl_api_latency"),
            ("osdpl_api_status"),
        ]
    )
    def test_osdpl_api_services(self, metric_name):
        service_name = data_utils.rand_name()
        url = self.ocm.oc.auth["auth_url"]
        labels = {
            "service_name": service_name,
            "service_type": "multi-region-network-automation",
            "url": url,
        }
        self._test_osdpl_api_samples(metric_name, labels, 0, "Initial")

        self.service = self.service_create(service_name, type="tricircle")
        self.endpoint = self.endpoint_create(
            self.service["id"], "public", url=url
        )

        self._test_osdpl_api_samples(metric_name, labels, 1, "After create")

        self.endpoint_delete(self.endpoint["id"])
        self.service_delete(self.service["id"])

        self._test_osdpl_api_samples(metric_name, labels, 0, "After delete")

    def test_osdpl_api_status_no_service_type(self):
        service_name = data_utils.rand_name()
        url = self.ocm.oc.auth["auth_url"]
        labels = {
            "service_name": service_name,
            "service_type": "foo",
            "url": url,
        }
        self._test_osdpl_api_samples("osdpl_api_status", labels, 0, "Initial")

        self.service = self.service_create(service_name, type="tricircle")
        self.endpoint = self.endpoint_create(
            self.service["id"], "public", url=url
        )

        self._test_osdpl_api_samples(
            "osdpl_api_status", labels, 0, "After create"
        )

    def test_osdpl_api_success(self):
        service_name = data_utils.rand_name()
        url = self.ocm.oc.auth["auth_url"]
        labels = {
            "service_name": service_name,
            "service_type": "multi-region-network-automation",
            "url": url,
        }

        self.service = self.service_create(service_name, type="tricircle")
        self.endpoint = self.endpoint_create(
            self.service["id"], "public", url=url
        )

        metrics = self.get_collector_metrics(self.scrape_collector)
        metric = self.get_metric("osdpl_api_success", metrics)
        samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            samples[0].value, 1, "Service success metric is not correct."
        )
