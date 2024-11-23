import re
import unittest

from rockoon.tests.functional import base
from rockoon import settings
from rockoon import kube


class TlsProxyFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        if (
            not self.osdpl.obj["spec"]["features"]
            .get("ssl", {})
            .get("tls_proxy", {})
            .get("enabled", True)
        ):
            raise unittest.SkipTest("TLS proxy not enabled.")

    @property
    def ingress_pods(self):
        kube_api = kube.kube_client()
        return kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={"application": "ingress", "component": "server"},
        )

    def test_tls_proxy_deployed(self):
        pod = next(self.ingress_pods.iterator())
        for container in pod.obj["spec"]["containers"]:
            if container["name"] == "tls-proxy":
                return
        assert False, "Did not found tls-proxy container in containers."

    def test_fips_mode_activated(self):
        pod = next(self.ingress_pods.iterator())
        proxy_info = (
            pod.exec(
                command=["tls-proxy", "--version"], container="tls-proxy"
            )["stderr"]
            .split("\n")[0]
            .lower()
        )
        res = None
        for pattern in [
            r".*fips \[.*enabled=true.*",
            r".*fips enabled=true.*",
        ]:
            res = re.search(pattern, proxy_info)
            if res:
                break
        assert res, "FIPS not activated for TLS-proxy."
