from rockoon.exporter.constants import ServiceStatus
from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import waiters as wait
from rockoon.tests.functional import config

CONF = config.Config()


class CinderServiceCollectorFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    scrape_collector = "osdpl_cinder"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cinder_svcs = cls.ocm.volume_get_services()
        cls.cinder_number = len(cls.cinder_svcs)

        svc = [
            svc
            for svc in cls.cinder_svcs
            if svc["status"].lower() == "enabled"
        ][0]

        cls.cinder_svc_data = {"host": svc["host"], "binary": svc["binary"]}

    @classmethod
    def tearDownClass(cls):
        cls.ocm.volume_ensure_service_enabled(
            host=cls.cinder_svc_data["host"],
            binary=cls.cinder_svc_data["binary"],
        )

    @property
    def cinder_svc(self):
        return self.ocm.volume_get_services(**self.cinder_svc_data)[0]

    def test_service_state(self):
        metric = self.get_metric("osdpl_cinder_service_state")
        self.assertIsNotNone(metric)
        self.assertEqual(self.cinder_number, len(metric.samples))
        self.assertCountEqual(
            ["host", "zone", "binary"],
            metric.samples[0].labels.keys(),
        )

    def test_service_status(self):
        metric = self.get_metric("osdpl_cinder_service_status")
        self.assertIsNotNone(metric)
        self.assertEqual(self.cinder_number, len(metric.samples))
        self.assertCountEqual(
            ["host", "zone", "binary"],
            metric.samples[0].labels.keys(),
        )

    def test_service_status_disable(self):
        """Check metrics with enabled/disabled volume service."""

        metric_name = "osdpl_cinder_service_status"
        self.ocm.volume_ensure_service_disabled(
            host=self.cinder_svc_data["host"],
            binary=self.cinder_svc_data["binary"],
        )

        labels = {
            "host": self.cinder_svc["host"],
            "binary": self.cinder_svc["binary"],
        }

        wait.wait_for_service_status_state(
            self.get_volume_service_status,
            self.cinder_svc,
            "disabled",
            CONF.VOLUME_TIMEOUT,
            CONF.VOLUME_READY_INTERVAL,
        )

        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceStatus.disabled,
            f"Status of cinder service in exporter's metrics hasn't changed",
        )
        self.ocm.volume_ensure_service_enabled(
            host=self.cinder_svc_data["host"],
            binary=self.cinder_svc_data["binary"],
        )

        wait.wait_for_service_status_state(
            self.get_volume_service_status,
            self.cinder_svc,
            "enabled",
            CONF.VOLUME_TIMEOUT,
            CONF.VOLUME_READY_INTERVAL,
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceStatus.enabled,
            f"Status of cinder service in exporter's metrics hasn't changed",
        )
