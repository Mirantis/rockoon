from rockoon.tests.functional.exporter import base


class GlanceCollectorFunctionalTestCase(base.BaseFunctionalExporterTestCase):
    known_metrics = {
        "osdpl_glance_images": {"labels": []},
        "osdpl_glance_images_size": {"labels": []},
    }

    def test_osdpl_glance_images_value(self):
        images_number = len(list(self.ocm.oc.image.images()))
        metric = self.get_metric("osdpl_glance_images")
        self.assertTrue(metric.samples[0].value == images_number)

    def test_osdpl_glance_images_size(self):
        metric = self.get_metric("osdpl_glance_images_size")
        self.assertIsNotNone(metric)
        self.assertTrue(len(metric.samples) > 0)
