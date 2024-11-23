import argparse
from unittest import mock

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import cinder


class TestK8sCinderObjectsCollector(utils.BaseTestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(
            dest="subcommand", required=True
        )
        self.plugin = sos.SosReportShell(self.parser, self.subparsers)
        self.plugin.build_options()
        self.mock_kube_client = mock.MagicMock()

        mock_kube_client = mock.patch(
            "rockoon.kube.kube_client",
            return_value=self.mock_kube_client,
        )
        mock_kube_client.start()
        self.addCleanup(mock_kube_client.stop)

        pod_patcher = mock.patch("rockoon.kube.Pod")
        self.mock_pod = pod_patcher.start()
        self.mock_pod.name = "cinder-volume-0"
        self.addCleanup(pod_patcher.stop)

        mock_pod_objects = mock.patch("rockoon.kube.find")
        self.mock_pod_objects = mock_pod_objects.start()
        self.addCleanup(mock_pod_objects.stop)

        mock_dump_exec_result = mock.patch(
            "rockoon.osctl.plugins.sosreport.base.BaseLogsCollector.dump_exec_result"
        )
        self.mock_dump_exec_result = mock_dump_exec_result.start()
        self.addCleanup(mock_dump_exec_result.stop)

    def test_can_run_trace(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = cinder.CinderObjectsCollector(args, "/workspace", "trace")
        self.assertFalse(collector.can_run)

    def test_can_run_report(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        collector = cinder.CinderObjectsCollector(args, "/workspace", "report")
        self.assertTrue(collector.can_run)

    def test_get_tasks_all_components(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        collector = cinder.CinderObjectsCollector(args, "/workspace", "report")
        self.assertEqual(
            collector.get_tasks(),
            [
                (collector.collect_ceph_general_info, (), {}),
            ],
        )

    def test_get_tasks_all_component_neutron(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--component",
                "neutron",
                "--all-hosts",
                "report",
            ]
        )
        collector = cinder.CinderObjectsCollector(args, "/workspace", "report")
        self.assertEqual(collector.get_tasks(), [])

    def test_collect_ceph_general_info_no_pods(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        collector = cinder.CinderObjectsCollector(args, "/workspace", "report")
        self.mock_pod_objects.return_value = None
        res = collector.collect_ceph_general_info()
        self.assertEqual(None, res)
        self.mock_dump_exec_result.assert_not_called()

    def test_collect_ceph_general_info_pod_no_keyrings(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        self.mock_pod_objects.return_value = self.mock_pod
        self.mock_pod.exec.return_value = {"stdout": "ceph.conf", "stderr": ""}
        collector = cinder.CinderObjectsCollector(args, "/workspace", "report")
        collector.collect_ceph_general_info()
        self.mock_dump_exec_result.assert_not_called()

    def test_collect_ceph_general_info_pod_keyrings(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        self.mock_pod_objects.return_value = self.mock_pod
        self.mock_pod.exec.return_value = {
            "stdout": "ceph.client.cinder.keyring\nceph.conf",
            "stderr": "",
        }
        collector = cinder.CinderObjectsCollector(args, "/workspace", "repor")
        collector.collect_ceph_general_info()
        self.mock_pod.exec.assert_called()
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/cinder/ceph/ceph_status.txt", mock.ANY)]
        )
