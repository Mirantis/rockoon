import unittest

from rockoon.tests.functional.exporter import base


class MasakariCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_masakari_segments": {"labels": []},
        "osdpl_masakari_hosts": {"labels": []},
        #        "osdpl_masakari_segment_hosts": {"labels": ["segment"]},
    }

    def setUp(self):
        super().setUp()
        if not self.is_masakari_enabled():
            raise unittest.SkipTest("Instance HA service is not enabled")

    def is_masakari_enabled(self):
        return "instance-ha" in self.osdpl.obj["spec"]["features"].get(
            "services", []
        )

    def test_osdpl_masakari_hosts_value(self):
        hosts = 0
        for segment in self.ocm.oc.ha.segments():
            segment_hosts = len(list(self.ocm.oc.ha.hosts(segment["uuid"])))
            hosts += segment_hosts
        metric = self.get_metric("osdpl_masakari_hosts")
        self.assertTrue(metric.samples[0].value == hosts)

    def test_osdpl_masakari_segment_hosts_value(self):
        for segment in self.ocm.oc.ha.segments():
            segment_hosts = len(list(self.ocm.oc.ha.hosts(segment["uuid"])))
            metric = self.get_metric("osdpl_masakari_segment_hosts")
            samples = self.filter_metric_samples(
                metric, {"segment": segment["name"]}
            )
            self.assertTrue(samples[0].value == segment_hosts)

    def test_osdpl_masakari_segments_value(self):
        segments = len(list(self.ocm.oc.ha.segments()))
        metric = self.get_metric("osdpl_masakari_segments")
        self.assertTrue(metric.samples[0].value == segments)
