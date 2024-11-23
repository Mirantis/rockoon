from datetime import datetime
from rockoon.tests.functional.exporter import base
from rockoon.osdplstatus import OpenStackDeploymentStatus
from parameterized import parameterized


class CredentialsCollectorFunctionalTestCase(
    base.BaseFunctionalExporterTestCase
):
    def setUp(self):
        super().setUp()
        self.metric = self.get_metric("osdpl_credentials_rotation_timestamp")
        self.osdplst = OpenStackDeploymentStatus(
            self.osdpl.name, self.osdpl.namespace
        )

    def test_metric_present(self):
        self.assertIsNotNone(self.metric)

    @parameterized.expand(
        [
            ("admin"),
            ("service"),
        ]
    )
    def test_rotation_samples(self, creds_type):
        labels = {"type": creds_type}
        samples = self.filter_metric_samples(self.metric, labels)
        self.assertEqual(1, len(samples))
        status_ts = self.osdplst.get_credentials_rotation_status(creds_type)[
            "timestamp"
        ]
        status_unix_ts = datetime.strptime(
            status_ts, "%Y-%m-%d %H:%M:%S.%f"
        ).timestamp()
        self.assertEqual(status_unix_ts, samples[0].value)
