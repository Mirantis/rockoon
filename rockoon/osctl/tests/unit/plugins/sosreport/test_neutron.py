import argparse
from unittest import mock
import json

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import neutron


class TestK8sNeutronObjectsCollector(utils.BaseTestCase):
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
        self.mock_pod.name = "l3-agent-1"
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
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "trace"
        )
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
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "report"
        )
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
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "report"
        )
        collector.hosts = ["host-1"]
        self.assertEqual(
            collector.get_tasks(),
            [
                (collector.collect_ovs_info, ("host-1",), {}),
                (collector.collect_namespaces_info, ("host-1",), {}),
            ],
        )

    def test_get_tasks_all_component_nova(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--component",
                "nova",
                "--all-hosts",
                "report",
            ]
        )
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "report"
        )
        collector.hosts = ["host-1"]
        self.assertEqual(collector.get_tasks(), [])

    def test_collect_namespaces_info_no_pods(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "repor"
        )
        self.mock_pod_objects.return_value.filter.return_value = []
        res = collector.collect_namespaces_info("host-1")
        self.assertEqual(None, res)

    @mock.patch.object(json, "loads")
    def test_collect_namespaces_info_pod_no_namespaces(self, mock_json_loads):
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
        mock_json_loads.return_value = ""
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "repor"
        )
        collector.collect_namespaces_info("host-1")
        self.mock_pod.exec.assert_called()
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/neutron/host-1/ip_addr.txt", mock.ANY)]
        )

    @mock.patch.object(json, "loads")
    def test_collect_namespaces_info_pod_namespaces(self, mock_json_loads):
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
        mock_json_loads.return_value = [{"name": "bar"}, {"name": "foo"}]
        collector = neutron.NeutronObjectsCollector(
            args, "/workspace", "repor"
        )
        collector.collect_namespaces_info("host-1")
        self.mock_pod.exec.assert_called()
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/neutron/host-1/ip_addr.txt", mock.ANY)]
        )
        self.mock_dump_exec_result.assert_has_calls(
            [mock.call("/workspace/neutron/host-1/foo/ip_addr.txt", mock.ANY)]
        )
