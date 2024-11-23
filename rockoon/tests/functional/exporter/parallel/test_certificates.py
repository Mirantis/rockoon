import unittest

from rockoon.tests.functional.exporter import base


class CertificatesCollectorFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    def setUp(self):
        super().setUp()
        self.metric = self.get_metric("osdpl_certificate_expiry")

    def test_metric_present(self):
        self.assertIsNotNone(self.metric)

    def test_mandatory_samples(self):
        for identifier in ["keystone_public", "octavia_amphora_ca"]:
            labels = {"identifier": identifier}
            samples = self.filter_metric_samples(self.metric, labels)
            self.assertEqual(1, len(samples))

    def test_libvirt_certs(self):
        if (
            not self.osdpl.obj["spec"]["features"]
            .get("nova", {})
            .get("libvirt", {})
            .get("tls", {})
            .get("enabled", False)
        ):
            raise unittest.SkipTest("Libvirt is not configured with TLS")
        for identifier in [
            "libvirt_server_ca",
            "libvirt_vnc_client",
            "libvirt_vnc_server",
        ]:
            labels = {"identifier": identifier}
            samples = self.filter_metric_samples(self.metric, labels)
            self.assertEqual(1, len(samples))
