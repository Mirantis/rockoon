from rockoon.tests.functional.exporter import base


class HorizonCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_horizon_login_success": {
            "labels": [
                "authentication_method",
                "url",
                "user_domain_name",
                "username",
            ]
        },
        "osdpl_horizon_login_latency": {"labels": ["type", "url"]},
    }
    scrape_collector = "osdpl_horizon"

    def test_osdpl_horizon_login_success(self):
        metric = self.get_metric_after_refresh(
            "osdpl_horizon_login_success", self.scrape_collector
        )
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
        self.assertTrue(
            metric.samples[0].value == 1.0, "Login to Horizon failed"
        )

    def test_horizon_login_latency(self):
        metric = self.get_metric_after_refresh(
            "osdpl_horizon_login_latency", self.scrape_collector
        )
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
        for sample in metric.samples:
            self.assertTrue(
                sample.value < 120.0,
                "Login to Horizon took more than 120 seconds",
            )
