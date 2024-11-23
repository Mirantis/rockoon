from rockoon.exporter.constants import ServiceStatus
from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import waiters as wait
from rockoon.tests.functional import config

CONF = config.Config()


class NeutronCollectorSerialFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    scrape_collector = "osdpl_neutron"

    def setUp(self):
        super().setUp()
        svc = [
            svc
            for svc in self.ocm.network_get_agents()
            if svc["is_admin_state_up"] is True
        ][0]

        self.network_svc_data = {"host": svc["host"], "binary": svc["binary"]}

    @property
    def network_svc(self):
        return list(self.ocm.network_get_agents(**self.network_svc_data))[0]

    def tearDown(self):
        self.ocm.network_ensure_agent_enabled(self.network_svc)
        super().tearDown()

    def test_agent_status_enabled_disabled(self):
        metric_name = "osdpl_neutron_agent_status"
        self.ocm.network_ensure_agent_disabled(self.network_svc)
        labels = {
            "host": self.network_svc["host"],
            "binary": self.network_svc["binary"],
        }
        wait.wait_for_service_status_state(
            self.get_neutron_agent_status,
            self.network_svc,
            False,
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
            f"Status of neutron agent in exporter's metrics hasn't changed",
        )

        self.ocm.network_ensure_agent_enabled(self.network_svc)
        wait.wait_for_service_status_state(
            self.get_neutron_agent_status,
            self.network_svc,
            True,
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
            f"Status of neutron agent in exporter's metrics hasn't changed",
        )
