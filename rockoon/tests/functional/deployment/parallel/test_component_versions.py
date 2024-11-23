import re
import unittest

from parameterized import parameterized
from rockoon.tests.functional import base
from rockoon import constants
from rockoon import settings
from rockoon import kube


class ComponentVersionsFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        openstack_version = self.osdpl.obj["spec"]["openstack_version"]
        if (
            constants.OpenStackVersion[openstack_version]
            < constants.OpenStackVersion["antelope"]
        ):
            raise unittest.SkipTest(
                "Skip component version checking for releases lower than Antelope"
            )

        self.check_scheme = {
            "ceph": [
                {
                    "pkg_names": ["ceph-common"],
                    "pkg_type": "dpkg",
                    "check_pods": [
                        "libvirt",
                        "cinder_volume",
                        "glance_api",
                        "nova_compute",
                        "manila_api",
                    ],
                },
            ],
            "libvirt": [
                {
                    "pkg_names": ["libvirt0:amd64", "qemu-utils"],
                    "pkg_type": "dpkg",
                    "check_pods": [
                        "libvirt",
                        "nova_compute",
                    ],
                },
            ],
            "librbd": [
                {
                    "pkg_names": ["librbd1", "python3-rbd"],
                    "pkg_type": "dpkg",
                    "check_pods": [
                        "libvirt",
                        "cinder_volume",
                        "glance_api",
                        "nova_compute",
                    ],
                },
            ],
        }

        self.pods_scheme = {
            "libvirt": {
                "application": "libvirt",
                "component": "libvirt",
                "container": "libvirt",
            },
            "cinder_volume": {
                "application": "cinder",
                "component": "volume",
                "container": "cinder-volume",
            },
            "glance_api": {
                "application": "glance",
                "component": "api",
                "container": "glance-api",
            },
            "nova_compute": {
                "application": "nova",
                "component": "compute",
                "container": "nova-compute",
            },
            "manila_api": {
                "application": "manila",
                "component": "api",
                "container": "manila-api",
            },
        }

    def _get_pkg_version(self, pkg_type, pkg_name, pod, container):
        if pkg_type == "pip":
            command = ["pip", "show", pkg_name]
        elif pkg_type == "dpkg":
            command = ["dpkg", "-s", pkg_name]
        else:
            assert False, f"Unsupported version type: {pkg_type}"
        pod_stdout = pod.exec(command, container=container)["stdout"]
        match = re.search(r"^Version:\s*(.+)$", pod_stdout, re.MULTILINE)
        self.assertTrue(
            match,
            f"Failed to get version of {pkg_name} in pod: {pod}",
        )
        pkg_version = match.group(1).strip()
        return pkg_version

    def _get_pod_scheme(self, check_pod):
        return self.pods_scheme[check_pod]

    @parameterized.expand(
        [
            ("ceph"),
            ("libvirt"),
            ("librbd"),
        ]
    )
    def test_check_package_version_are_same(self, scheme_name):
        kube_api = kube.kube_client()
        have_different_pkg_version = {}
        for scheme in self.check_scheme[scheme_name]:
            for pkg_name in scheme["pkg_names"]:
                pkg_versions = {}
                for check_pod in scheme["check_pods"]:
                    pod_scheme = self._get_pod_scheme(check_pod)
                    pods = kube.Pod.objects(kube_api).filter(
                        namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
                        selector={
                            "application": pod_scheme["application"],
                            "component": pod_scheme["component"],
                        },
                    )
                    pods = [pod for pod in pods]
                    if not pods:
                        continue
                    pod = pods[0]
                    pkg_versions[pod] = self._get_pkg_version(
                        scheme["pkg_type"],
                        pkg_name,
                        pod,
                        pod_scheme["container"],
                    )
                self.assertTrue(
                    pkg_versions,
                    f"Failed to get version of {pkg_name} in pods: {scheme['check_pods']}",
                )
                if len(set(pkg_versions.values())) != 1:
                    have_different_pkg_version[pkg_name] = pkg_versions
        self.assertFalse(
            have_different_pkg_version,
            f"Packages have different version: {have_different_pkg_version}",
        )
