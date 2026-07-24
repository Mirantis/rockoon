import os.path
from parameterized import parameterized
from rockoon import kube, settings
from rockoon.tests.functional import base
import socket
import ssl
import tempfile
import time

TLS_VERSION_MAP = {
    "tlsv1.0": ssl.TLSVersion.TLSv1,
    "tlsv1.1": ssl.TLSVersion.TLSv1_1,
    "tlsv1.2": ssl.TLSVersion.TLSv1_2,
    "tlsv1.3": ssl.TLSVersion.TLSv1_3,
}


def cipersuite_check_custom_name_func(testcase_func, param_num, param):
    return "%s_%s" % (
        testcase_func.__name__,
        parameterized.to_safe_name("_".join(str(x) for x in param.args)),
    )


class FipsFunctionalTestCase(base.BaseFunctionalTestCase):
    test_host = "keystone.it.just.works"
    test_port = 443

    @classmethod
    def _count_container_restarts(cls):
        kube_api = kube.kube_client()
        ingress_pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={"application": "ingress", "component": "server"},
        )
        total = 0
        for pod in ingress_pods.iterator():
            for container in pod.obj["status"]["containerStatuses"]:
                total += container["restartCount"]
        return total

    @classmethod
    def setUpClass(cls):
        super(FipsFunctionalTestCase, cls).setUpClass()
        keystone_secret = kube.find(
            kube.Secret,
            "keystone-ca-bundle",
            settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            silent=True,
        )
        cls.assertIsNotNone(
            keystone_secret,
            f"Can't get keystone-ca-bundle secret in {settings.OSCTL_OS_DEPLOYMENT_NAMESPACE} namespace.",
        )
        secret_data = keystone_secret.data_decoded
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=False) as f:
            f.write(secret_data["ca_bundle"].encode("utf-8"))
            cls.ca_bundle = f.name
        cls.restarts = cls._count_container_restarts()

    @classmethod
    def tearDownClass(cls):
        super(FipsFunctionalTestCase, cls).tearDownClass()
        if cls.ca_bundle:
            os.remove(cls.ca_bundle)
        current_restarts = cls._count_container_restarts()
        assert (
            cls.restarts == current_restarts
        ), f"During the test, {current_restarts - cls.restarts} Ingress containers were restarted"

    def _test_ciphersuite(
        self, host, port, test_tls_version, test_cipher, expected_state
    ):
        # this sleep was added for reducing requests frequency during testing
        time.sleep(0.5)
        # Create a TLS context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_version = TLS_VERSION_MAP.get(test_tls_version.lower())
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.load_verify_locations(self.ca_bundle)
        if test_cipher.lower() != "auto":
            # Explicitly restrict the context to ONLY use the target cipher
            context.set_ciphers(test_cipher)

        # Create network socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)  # Avoid hanging indefinitely

        test_passed = False
        secure_sock = None
        try:
            # Wrap the socket with our strict TLS context
            secure_sock = context.wrap_socket(sock, server_hostname=host)
            secure_sock.connect((host, port))
            test_passed = expected_state == "positive"
        except ssl.SSLError:
            # Handshake failure means the remote libvirt doesn't allow the cipher
            test_passed = expected_state == "negative"
        finally:
            if secure_sock:
                secure_sock.close()
            else:
                sock.close()

        self.assertTrue(test_passed)

    @parameterized.expand(
        [
            # Any connections with TLS 1 and TLS 1.1 should fail
            ("TLSv1.0", "auto", "negative"),
            ("TLSv1.1", "auto", "negative"),
            # The list of cipher suites for TLS 1.2 was obtained from the output
            # of the following command:
            # openssl ciphers -v 'ALL' | grep "TLSv1.2" | awk '{print $1}'
            ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", "positive"),
            ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "positive"),
            ("TLSv1.2", "ECDHE-ECDSA-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-DSS-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-RSA-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "DHE-RSA-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES256-CCM8", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES256-CCM", "negative"),
            ("TLSv1.2", "DHE-RSA-AES256-CCM8", "negative"),
            ("TLSv1.2", "DHE-RSA-AES256-CCM", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "ECDHE-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-DSS-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-RSA-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "ADH-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-RSA-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES128-CCM8", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES128-CCM", "negative"),
            ("TLSv1.2", "DHE-RSA-AES128-CCM8", "negative"),
            ("TLSv1.2", "DHE-RSA-AES128-CCM", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-RSA-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "ADH-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES256-SHA384", "negative"),
            ("TLSv1.2", "ECDHE-RSA-AES256-SHA384", "negative"),
            ("TLSv1.2", "DHE-RSA-AES256-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-AES256-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-CAMELLIA256-SHA384", "negative"),
            ("TLSv1.2", "ECDHE-RSA-CAMELLIA256-SHA384", "negative"),
            ("TLSv1.2", "DHE-RSA-CAMELLIA256-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-CAMELLIA256-SHA256", "negative"),
            ("TLSv1.2", "ADH-AES256-SHA256", "negative"),
            ("TLSv1.2", "ADH-CAMELLIA256-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-AES128-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-RSA-AES128-SHA256", "negative"),
            ("TLSv1.2", "DHE-RSA-AES128-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-AES128-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-ECDSA-CAMELLIA128-SHA256", "negative"),
            ("TLSv1.2", "ECDHE-RSA-CAMELLIA128-SHA256", "negative"),
            ("TLSv1.2", "DHE-RSA-CAMELLIA128-SHA256", "negative"),
            ("TLSv1.2", "DHE-DSS-CAMELLIA128-SHA256", "negative"),
            ("TLSv1.2", "ADH-AES128-SHA256", "negative"),
            ("TLSv1.2", "ADH-CAMELLIA128-SHA256", "negative"),
            ("TLSv1.2", "RSA-PSK-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-PSK-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "RSA-PSK-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "DHE-PSK-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "ECDHE-PSK-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "DHE-PSK-AES256-CCM8", "negative"),
            ("TLSv1.2", "DHE-PSK-AES256-CCM", "negative"),
            ("TLSv1.2", "RSA-PSK-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "DHE-PSK-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "AES256-CCM8", "negative"),
            ("TLSv1.2", "AES256-CCM", "negative"),
            ("TLSv1.2", "ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "PSK-AES256-GCM-SHA384", "negative"),
            ("TLSv1.2", "PSK-CHACHA20-POLY1305", "negative"),
            ("TLSv1.2", "PSK-AES256-CCM8", "negative"),
            ("TLSv1.2", "PSK-AES256-CCM", "negative"),
            ("TLSv1.2", "PSK-ARIA256-GCM-SHA384", "negative"),
            ("TLSv1.2", "RSA-PSK-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-PSK-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-PSK-AES128-CCM8", "negative"),
            ("TLSv1.2", "DHE-PSK-AES128-CCM", "negative"),
            ("TLSv1.2", "RSA-PSK-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "DHE-PSK-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "AES128-CCM8", "negative"),
            ("TLSv1.2", "AES128-CCM", "negative"),
            ("TLSv1.2", "ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "PSK-AES128-GCM-SHA256", "negative"),
            ("TLSv1.2", "PSK-AES128-CCM8", "negative"),
            ("TLSv1.2", "PSK-AES128-CCM", "negative"),
            ("TLSv1.2", "PSK-ARIA128-GCM-SHA256", "negative"),
            ("TLSv1.2", "AES256-SHA256", "negative"),
            ("TLSv1.2", "CAMELLIA256-SHA256", "negative"),
            ("TLSv1.2", "AES128-SHA256", "negative"),
            ("TLSv1.2", "CAMELLIA128-SHA256", "negative"),
            # The TLS 1.3 has its own mechanic for ciphersite management but
            # it didn't implement in Python 3.12 so we can't set cipher for testing
            # There is a patch https://github.com/python/cpython/commit/bacb7771fb0390a1ae7f83b7bec97e5ce1d60d26
            # that will allow TLS 1.3 ciphersuites management in the future Python
            # releases
            ("TLSv1.3", "auto", "positive"),
        ],
        name_func=cipersuite_check_custom_name_func,
    )
    def test_ssl_connection(self, tls_version, cipher, expected_state):
        self._test_ciphersuite(
            self.test_host, self.test_port, tls_version, cipher, expected_state
        )
