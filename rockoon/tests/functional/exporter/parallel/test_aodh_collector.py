import unittest

from rockoon.tests.functional.exporter import base


class AodhCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_aodh_alarms": {"labels": []},
    }

    def setUp(self):
        super().setUp()
        if not self.is_service_enabled("alarming"):
            raise unittest.SkipTest("Alarming service is not enabled")

    def test_osdpl_aodh_alarms_value(self):
        alarms_number = len(self.ocm.oc.alarm.get("/alarms").json())
        metric = self.get_metric("osdpl_aodh_alarms")
        self.assertTrue(metric.samples[0].value == alarms_number)
