import argparse
from unittest import mock

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import nova


class TestK8sNovaObjectsCollector(utils.BaseTestCase):
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
        self.mock_pod.name = "libvirt-1"
        self.addCleanup(pod_patcher.stop)

        mock_pod_objects = mock.patch("rockoon.kube.Pod.objects")
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
        collector = nova.NovaObjectsCollector(args, "/workspace", "trace")
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
        collector = nova.NovaObjectsCollector(args, "/workspace", "report")
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
        collector = nova.NovaObjectsCollector(args, "/workspace", "report")
        collector.hosts = ["host-1"]
        self.assertEqual(
            collector.get_tasks(),
            [
                (collector.collect_instances_info, ("host-1",), {}),
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
        collector = nova.NovaObjectsCollector(args, "/workspace", "report")
        collector.hosts = ["host-1"]
        self.assertEqual(collector.get_tasks(), [])

    def test_collect_instances_info_no_pods(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = nova.NovaObjectsCollector(args, "/workspace", "repor")
        self.mock_pod_objects.return_value.filter.return_value = []
        res = collector.collect_instances_info("host-1")
        self.assertEqual(None, res)

    def test_collect_instances_info_pod_no_instances(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        self.mock_pod_objects.return_value.filter.return_value = [
            self.mock_pod
        ]
        self.mock_pod.exec.return_value = {"stdout": "", "stderr": ""}
        collector = nova.NovaObjectsCollector(args, "/workspace", "repor")
        collector.collect_instances_info("host-1")
        self.mock_pod.exec.assert_called()
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/nova/host-1/nodeinfo.txt", mock.ANY)]
        )

    def test_collect_instances_info_pod_instances(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        self.mock_pod_objects.return_value.filter.return_value = [
            self.mock_pod
        ]
        self.mock_pod.exec.return_value = {
            "stdout": "instance-1",
            "stderr": "",
        }
        collector = nova.NovaObjectsCollector(args, "/workspace", "repor")
        collector.collect_instances_info("host-1")
        self.mock_pod.exec.assert_called()
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/nova/host-1/nodeinfo.txt", mock.ANY)]
        )
        self.mock_dump_exec_result.assert_has_calls(
            [
                mock.call(
                    "/workspace/nova/host-1/instance-1/dumpxml.txt", mock.ANY
                )
            ]
        )
