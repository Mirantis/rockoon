import re

from parameterized import parameterized
from rockoon.tests.functional import base
from rockoon import settings
from rockoon import kube
from packaging.version import Version


class ComponentFilePermissionsFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        if Version(self.osdpl.obj["status"]["version"]) < Version("0.17.1"):
            self.skipTest(
                "This test requires rockoon version " "0.17.2 and greater"
            )
        self.maxDiff = None

    def _container_files_with_wrong_prems(
        self, pod, container, application, target_directories=None
    ):
        res = []
        search_pattern = rf"^-rw-r----- [\d]+ [\S]+ {application} .*$"
        target_directories = target_directories or [f"/etc/{application}"]
        dirs = " ".join(target_directories)
        command = [
            "bash",
            "-c",
            f"find {dirs} -type f | xargs -I {{}} ls -lah {{}}",
        ]
        pod_stdout = pod.exec(command, container=container)["stdout"]
        for line in pod_stdout.splitlines():
            if not re.search(search_pattern, line):
                if line not in res:
                    res.append(line)
        return res

    def _get_files_with_wrong_perms(self, application, skip_containers=None):
        failed_files = {}
        kube_api = kube.kube_client()
        skip_containers = skip_containers or []
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={
                "application": application,
            },
            field_selector={"status.phase": "Running"},
        )
        for pod in pods:
            for container in pod.obj["spec"]["containers"]:
                cname = container["name"]
                if cname in skip_containers:
                    continue
                failed = self._container_files_with_wrong_prems(
                    pod, cname, application
                )
                if failed:
                    failed_files.setdefault(cname, [])
                    failed_files[cname] = failed
        return failed_files

    @parameterized.expand(
        [
            ("aodh"),
            ("barbican"),
            ("ceilometer"),
            ("cinder"),
            ("glance"),
            ("gnocchi"),
            ("heat"),
            ("horizon"),
            ("keystone"),
            ("manila"),
            ("masakari"),
            ("neutron"),
            ("nova"),
            ("octavia"),
            ("placement"),
        ]
    )
    def test_check_file_permissions(self, application):
        failed_files = self._get_files_with_wrong_perms(application)
        self.assertEqual(
            failed_files,
            {},
            f"Detected files with wrong permissions for {application}",
        )

    def test_check_file_premissions_designate(self):
        application = "designate"
        failed_files = self._get_files_with_wrong_perms(
            application, ["designate-powerdns"]
        )
        self.assertEqual(
            failed_files,
            {},
            f"Detected files with wrong permissions for {application}",
        )
