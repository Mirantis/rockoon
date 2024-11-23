from rockoon.tests.functional.exporter import base


class HeatCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_heat_stacks": {"labels": []},
    }

    def test_heat_stacks(self):
        metric = self.get_metric("osdpl_heat_stacks")
        stacks = len(list(self.ocm.oc.orchestration.stacks()))
        self.assertEqual(int(metric.samples[0].value), stacks)
