import json
import unittest

from rockoon.tests.functional import base
from rockoon import constants
from rockoon import kube


class StacklightSecretFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        if not self.secret:
            raise unittest.SkipTest("Stacklight service is not enabled")
        self.conf_json = json.loads(self.secret.data_decoded["conf.json"])

    @property
    def secret(self):
        return kube.find(
            kube.Secret,
            constants.OPENSTACK_STACKLIGHT_CONFIG_SECRET,
            constants.OPENSTACK_STACKLIGHT_SHARED_NAMESPACE,
            silent=True,
        )

    def test_cloudprober(self):
        cloudprober_enabled = self.is_service_enabled("cloudprober")
        self.assertEqual(
            cloudprober_enabled,
            self.conf_json["exporters"]["cloudprober"]["enabled"],
            f"Cloudprober stacklight exporter configuration is not correct.",
        )

    def test_portprober(self):
        self.assertEqual(
            self.neturon_portprober_enabled,
            self.conf_json["exporters"]["portprober"]["enabled"],
            f"Portprober stacklight exporter configuration is not correct.",
        )
