import unittest
import pytest

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

    def libvirt_pod(self, host):
        kube_api = kube.kube_client()
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={"application": "libvirt", "component": "libvirt"},
        )
        for pod in pods:
            if pod.obj["spec"].get("nodeName") == host:
                return pod

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
