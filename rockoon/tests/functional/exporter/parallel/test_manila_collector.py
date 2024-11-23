import unittest

from rockoon.tests.functional.exporter import base


class ManilaCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):

    known_metrics = {
        "osdpl_manila_shares": {"labels": []},
    }

    def setUp(self):
        super().setUp()
        if not self.is_manila_enabled():
            raise unittest.SkipTest(
                "Shared file system service is not enabled"
            )

    def is_manila_enabled(self):
        return "shared-file-system" in self.osdpl.obj["spec"]["features"].get(
            "services", []
        )

    def test_osdpl_manila_shares_value(self):
        shares_number = len(list(self.ocm.oc.share.shares(all_tenants=True)))
        metric = self.get_metric("osdpl_manila_shares")
        self.assertTrue(metric.samples[0].value == shares_number)
