from rockoon.tests.functional.exporter import base
from rockoon.tests.functional import data_utils


class KeystoneCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_keystone_projects": {"labels": []},
        "osdpl_keystone_users": {"labels": []},
        "osdpl_keystone_domains": {"labels": []},
    }

    scrape_collector = "osdpl_keystone"

    def setUp(self):
        super().setUp()
        self.domain_name = data_utils.rand_name()

    def _test_osdpl_keystone_domains(self, metric_name, expected_num, phase):
        metric = self.get_metric_after_refresh(
            metric_name, self.scrape_collector
        )
        self.assertEqual(
            metric.samples[0].value,
            expected_num,
            f"{phase}: The number of domains is not correct.",
        )

    def test_keystone_projects_value(self):
        projects_total = 0
        for domain in self.ocm.oc.identity.domains():
            projects_total += len(
                list(self.ocm.oc.identity.projects(domain_id=domain["id"]))
            )
        metric = self.get_metric("osdpl_keystone_projects")
        self.assertEqual(
            projects_total,
            metric.samples[0].value,
        )

    def test_keystone_users_value(self):
        users_total = 0
        for domain in self.ocm.oc.identity.domains():
            users_total += len(
                list(self.ocm.oc.identity.users(domain_id=domain["id"]))
            )
        metric = self.get_metric("osdpl_keystone_users")
        self.assertEqual(
            users_total,
            metric.samples[0].value,
        )

    def test_keystone_domains(self):
        metric_name = "osdpl_keystone_domains"
        domains_total = len(list(self.ocm.oc.identity.domains()))

        self._test_osdpl_keystone_domains(
            metric_name, domains_total, "Initial"
        )

        # Add one domain
        domain = self.create_domain(self.domain_name)

        # Refresh and check new domain is in list:
        self._test_osdpl_keystone_domains(
            metric_name, domains_total + 1, "After create"
        )

        # Delete domain:
        self.delete_domain(domain["id"])

        # Check that domain had been deleted from list:
        self._test_osdpl_keystone_domains(
            metric_name, domains_total, "After delete"
        )
