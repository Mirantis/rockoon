from rockoon.exporter.constants import ServiceState, ServiceStatus
from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import waiters as wait
from rockoon.tests.functional import config

CONF = config.Config()


class NovaCollectorSerialFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    scrape_collector = "osdpl_nova"

    def setUp(self):
        super().setUp()
        svc = [
            svc
            for svc in self.ocm.compute_get_services()
            if svc["status"].lower() == "enabled"
        ][0]

        self.compute_svc_data = {"host": svc["host"], "binary": svc["binary"]}

    @property
    def compute_svc(self):
        return self.ocm.compute_get_services(**self.compute_svc_data)[0]

    def tearDown(self):
        self.ocm.compute_ensure_service_enabled(self.compute_svc)
        self.ocm.compute_ensure_service_force_down(self.compute_svc, False)
        super().tearDown()

    def test_service_status_enabled_disabled(self):
        metric_name = "osdpl_nova_service_status"
        self.ocm.compute_ensure_service_disabled(
            self.compute_svc,
            "Functional test test_service_status_enabled_disabled",
        )
        labels = {
            "host": self.compute_svc["host"],
            "binary": self.compute_svc["binary"],
        }
        wait.wait_for_service_status_state(
            self.get_compute_service_status,
            self.compute_svc,
            "disabled",
            CONF.COMPUTE_TIMEOUT,
            CONF.COMPUTE_BUILD_INTERVAL,
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceStatus.disabled,
            f"Status of nova service in exporter's metrics hasn't changed",
        )

        self.ocm.compute_ensure_service_enabled(self.compute_svc)
        wait.wait_for_service_status_state(
            self.get_compute_service_status,
            self.compute_svc,
            "enabled",
            CONF.COMPUTE_TIMEOUT,
            CONF.COMPUTE_BUILD_INTERVAL,
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceStatus.enabled,
            f"Status of nova service in exporter's metrics hasn't changed",
        )

    def test_service_state_up_down(self):
        metric_name = "osdpl_nova_service_state"
        self.ocm.compute_ensure_service_force_down(self.compute_svc, True)
        labels = {
            "host": self.compute_svc["host"],
            "binary": self.compute_svc["binary"],
        }
        wait.wait_for_service_status_state(
            self.get_compute_service_state,
            self.compute_svc,
            "down",
            CONF.COMPUTE_TIMEOUT,
            CONF.COMPUTE_BUILD_INTERVAL,
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceState.down,
            f"State of nova service in exporter's metrics hasn't changed",
        )

        self.ocm.compute_ensure_service_force_down(self.compute_svc, False)
        wait.wait_for_service_status_state(
            self.get_compute_service_state,
            self.compute_svc,
            "up",
            CONF.COMPUTE_TIMEOUT,
            CONF.COMPUTE_BUILD_INTERVAL,
        )
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        service_samples = self.filter_metric_samples(metric, labels)
        self.assertEqual(
            service_samples[0].value,
            ServiceState.up,
            f"State of nova service in exporter's metrics hasn't changed",
        )
