import unittest
import pytest
import json
import os
import tempfile

from parameterized import parameterized
from rockoon.tests.functional import base
from rockoon import constants, kube, settings


@pytest.mark.xdist_group("exporter-compute-network")
class TestVncTLSTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        if (
            not self.osdpl.obj["spec"]["features"]
            .get("nova", {})
            .get("console", {})
            .get("novnc", {})
            .get("tls", {})
            .get("enabled", False)
        ):
            raise unittest.SkipTest("VNC TLS is not enabled.")

    def test_novnc_tls(self):
        server = self.server_create()
        server = self.ocm.oc.get_server(server["id"])
        host = server.compute_host
        libvirt_pod = self.libvirt_pod(host)
        processes = libvirt_pod.exec(
            ["ps", "axwwwocommand"], container="libvirt", raise_on_error=True
        )["stdout"]
        qemu_psline = ""
        for line in processes.splitlines():
            if (
                "qemu-system" in line
                and f"guest={server['OS-EXT-SRV-ATTR:instance_name']}" in line
            ):
                qemu_psline = line
                break
        openstack_version = self.osdpl.obj["spec"]["openstack_version"]
        tls_pattern = (
            "tls-creds-x509"
            if constants.OpenStackVersion[openstack_version]
            > constants.OpenStackVersion["queens"]
            else "x509verify"
        )
        self.assertTrue(
            tls_pattern in line,
            f"The tls pattern string '{tls_pattern}'"
            f" not found in qemu-system process line {qemu_psline}",
        )


class LibvirtFipsFunctionalTestCase(base.BaseFunctionalTestCase):
    """Check Libvirt and QEMU Fips compliance"""

    @classmethod
    def setUpClass(cls):
        super(LibvirtFipsFunctionalTestCase, cls).setUpClass()
        if (
            not cls.osdpl.obj["spec"]["features"]
            .get("nova", {})
            .get("libvirt", {})
            .get("tls", {})
            .get("enabled", False)
        ):
            raise unittest.SkipTest("Libvirt TLS is not enabled.")
        libvirt_secret = kube.find(
            kube.Secret,
            "libvirt-server-certs",
            settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            silent=True,
        )
        cls.assertIsNotNone(
            libvirt_secret,
            f"Can't get libvirt-ca-bundle secret in {settings.OSCTL_OS_DEPLOYMENT_NAMESPACE} namespace.",
        )
        secret_data = libvirt_secret.data_decoded
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=False) as f:
            f.write(secret_data["ca.crt"].encode("utf-8"))
            cls.ca_bundle = f.name

    def setUp(self):
        super(LibvirtFipsFunctionalTestCase, self).setUp()
        kube_api = kube.kube_client()
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={
                "application": "libvirt",
                "component": "libvirt",
            },
        )
        pods = [pod for pod in pods]
        self.assertTrue(
            pods,
            "Failed to get Libvirt pods.",
        )
        self.libvirt_pod = pods[0]

    @classmethod
    def tearDownClass(cls):
        super(LibvirtFipsFunctionalTestCase, cls).tearDownClass()
        if cls.ca_bundle:
            os.remove(cls.ca_bundle)

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
            ("TLSv1.2", "AES256-GCM-SHA384", "positive"),
            ("TLSv1.2", "AES256-CCM8", "negative"),
            ("TLSv1.2", "AES256-CCM", "positive"),
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
            ("TLSv1.2", "AES128-GCM-SHA256", "positive"),
            ("TLSv1.2", "AES128-CCM8", "negative"),
            ("TLSv1.2", "AES128-CCM", "positive"),
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
        name_func=base.default_custom_name_func,
    )
    def test_ssl_connection(self, tls_version, cipher, expected_state):
        self.check_ciphersuite(
            self.libvirt_pod.obj["status"]["hostIP"],
            16514,
            tls_version,
            cipher,
            expected_state,
            self.ca_bundle,
        )

    def test_libraries_mode(self):
        response = self.exec_script_in_pod(
            self.libvirt_pod, "libvirt", "check_libs_fips_mode.py"
        )
        self.assertTrue(response["error_json"]["status"] == "Success")
        result = json.loads(response["stdout"])
        self.assertTrue(result["gnutls"] and result["libcrypto"])
