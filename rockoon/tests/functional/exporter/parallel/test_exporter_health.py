from rockoon.tests.functional.exporter import base


class ExporterHealthCollectorFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    def test_scrape_collector_duration_seconds(self):
        metric = self.get_metric("osdpl_scrape_collector_duration_seconds")
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)

    def test_osdpl_scrape_collector_success(self):
        metric = self.get_metric("osdpl_scrape_collector_success")
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
