import unittest

from rockoon.tests.functional import base
from rockoon import settings
from rockoon import kube

DEFAULT_REPLICAS = 3
DEFAULT_NODE_LABELS = {
    "node_selector_key": "openstack-control-plane",
    "node_selector_value": "enabled",
}


class CinderExtraBackendsFunctionalTestCase(base.BaseFunctionalTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        extra_backends = (
            cls.osdpl.obj["spec"]["features"]
            .get("cinder", {})
            .get("volume", {})
            .get("backends", {})
        )
        cls.enabled_volume_extra_backends = {}
        if extra_backends:
            for name, opts in extra_backends.items():
                if opts.get("enabled", True):
                    cls.enabled_volume_extra_backends.update({name: opts})
        if not cls.enabled_volume_extra_backends:
            raise unittest.SkipTest("No Cinder extra backends enabled.")

    def test_standalone_volume_sts(self):
        for name, opts in self.enabled_volume_extra_backends.items():
            if opts["type"] == "statefulset":
                configured_replicas = (
                    opts["values"]
                    .get("pod", {})
                    .get("replicas", {})
                    .get("volume", DEFAULT_REPLICAS)
                )
                configured_node_labels = (
                    opts["values"]
                    .get("labels", {})
                    .get("volume", DEFAULT_NODE_LABELS)
                )
                sts = kube.find(
                    kube.StatefulSet,
                    f"cinder-volume-{name.replace('_', '-')}",
                    namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
                    silent=True,
                )
                assert sts, f"There is no StatefulSet for {name} backend."
                self.assertEqual(
                    sts.obj["spec"]["replicas"],
                    configured_replicas,
                    f"Configured and deployed replicas are different for {name} backend.",
                )
                self.assertEqual(
                    sts.obj["spec"]["template"]["spec"]["nodeSelector"],
                    {
                        configured_node_labels[
                            "node_selector_key"
                        ]: configured_node_labels["node_selector_value"]
                    },
                    f"Configured and deployed nodeSelector labels are different for {name} backend.",
                )

    def test_volume_types(self):
        backend_volume_types = []
        volume_backends = set(
            x["extra_specs"]["volume_backend_name"]
            for x in self.ocm.oc.volume.types()
            if x["extra_specs"].get("volume_backend_name")
        )
        for name, opts in self.enabled_volume_extra_backends.items():
            for backend in opts["values"]["conf"]["cinder"]["DEFAULT"][
                "enabled_backends"
            ].split(","):
                backend_name = opts["values"]["conf"]["cinder"][backend][
                    "volume_backend_name"
                ]
                backend_volume_types.append(backend_name in volume_backends)
            assert backend_volume_types and all(
                backend_volume_types
            ), f"The backend {name} does not have corresponding volume type."
