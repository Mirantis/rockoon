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

    @property
    def secret(self):
        return kube.find(
            kube.Secret,
            constants.OPENSTACK_STACKLIGHT_SECRET,
            constants.OPENSTACK_STACKLIGHT_SHARED_NAMESPACE,
            silent=True,
        )

    def test_connection(self):
        secret_data = self.secret.data_decoded
        vhost = secret_data["vhost"].lstrip("/")

        for host_port in json.loads(secret_data["hosts"]):
            host, port = host_port.split(":")
            check_test_connection = self.check_rabbitmq_connection(
                secret_data["username"],
                secret_data["password"],
                host,
                port,
                vhost,
            )
            self.assertTrue(
                check_test_connection,
                f"Failed connection to RabbitMQ {host}:{port}/{vhost}",
            )
