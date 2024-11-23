import ssl
import tempfile
import unittest

from rockoon.tests.functional import base
from rockoon import constants
from rockoon import kube


class ExternalRmqNotificationsFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        if not self.external_notifications.get("enabled", False):
            raise unittest.SkipTest("External notifications not enabled.")

    @property
    def external_notifications(self):
        self.osdpl.reload()
        return (
            self.osdpl.obj["spec"]["features"]
            .get("messaging", {})
            .get("notifications", {})
            .get("external", {})
        )

    @property
    def external_notifications_topics(self):
        return self.external_notifications.get("topics", [])

    @property
    def secrets(self):
        res = []
        for secret in kube.Secret.objects(self.kube_api).filter(
            namespace=constants.OPENSTACK_EXTERNAL_NAMESPACE
        ):
            if secret.name.startswith("openstack-") and secret.name.endswith(
                "-notifications"
            ):
                res.append(secret)
        return res

    @property
    def service(self):
        return kube.find(
            kube.Service,
            constants.RABBITMQ_EXTERNAL_SERVICE,
            "openstack",
            silent=False,
        )

    def test_topics(self):
        self.assertIsNotNone(
            self.external_notifications_topics,
            "RabbitMQ has no external topics",
        )

    def test_service_exposed_outside(self):
        self.assertIsNotNone(self.service.loadbalancer_ips[0])

    def test_topics_count(self):
        self.assertEqual(
            len(self.external_notifications_topics),
            len(self.secrets),
            "Number of secrets not same as number of topics",
        )

    def test_external_secret_content(self):
        ext_ip_rabbitmq = self.service.loadbalancer_ips[0]
        ext_ports_rabbitmq = self.service.obj["spec"]["ports"]
        for creds_secret in self.secrets:
            secret_data = creds_secret.data_decoded
            self.assertEqual(
                ext_ip_rabbitmq, secret_data["hosts"], "Host mismatch"
            )
            self.assertEqual(
                True,
                all(
                    [
                        p["port"] == int(secret_data[f"port_{p['name']}"])
                        for p in ext_ports_rabbitmq
                    ]
                ),
                "Ports mismatch",
            )

    def test_connection_ssl(self):
        for creds_secret in self.secrets:
            secret_data = creds_secret.data_decoded
            certs = {
                "ca_certs": "ca_cert",
                "keyfile": "client_key",
                "certfile": "client_cert",
            }
            with tempfile.TemporaryDirectory() as tmpdir:
                # update secret keys with certificates file names
                for k, v in certs.items():
                    f = tempfile.NamedTemporaryFile(dir=tmpdir, delete=False)
                    certs[k] = f.name
                    f.write(secret_data[v].encode("utf-8"))
                    f.close()
                check_test_connection = self.check_rabbitmq_connection(
                    secret_data["username"],
                    secret_data["password"],
                    secret_data["hosts"],
                    secret_data["port_amqp-tls"],
                    secret_data["vhost"],
                    {**certs, "cert_reqs": ssl.CERT_REQUIRED},
                )

            self.assertTrue(
                check_test_connection,
                f"Failed connection to RabbitMQ vhost. Secret name {creds_secret.name}",
            )

    def test_connection_plain(self):
        for creds_secret in self.secrets:
            secret_data = creds_secret.data_decoded
            check_test_connection = self.check_rabbitmq_connection(
                secret_data["username"],
                secret_data["password"],
                secret_data["hosts"],
                secret_data["port_amqp"],
                secret_data["vhost"],
            )
            self.assertTrue(
                check_test_connection,
                f"Failed connection to RabbitMQ vhost. Secret name {creds_secret.name}",
            )
