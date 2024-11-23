import argparse
from unittest import mock
import yaml

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import k8s
from rockoon import kube


class TestK8sObjectsCollector(utils.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(
            dest="subcommand", required=True
        )
        self.plugin = sos.SosReportShell(self.parser, self.subparsers)
        self.plugin.build_options()
        self.mock_kube_client = mock.MagicMock()

        mock_kube_client = mock.patch.object(
            kube, "kube_client", return_value=self.mock_kube_client
        )
        mock_kube_client.start()
        self.addCleanup(mock_kube_client.stop)

        mock_node_objects = mock.patch("rockoon.kube.Node.objects")
        self.mock_node_obj = mock_node_objects.start()
        self.addCleanup(mock_node_objects.stop)

        self.mock_node = mock.patch("rockoon.kube.Node")
        self.mock_node.name = "node-1"
        self.mock_node.obj = {"foo": "bar"}

    def test_can_run_trace(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = k8s.K8sObjectsCollector(args, "/workspace", "trace")
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
        collector = k8s.K8sObjectsCollector(args, "/workspace", "report")
        self.assertTrue(collector.can_run)

    def test_get_tasks(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        collector = k8s.K8sObjectsCollector(args, "/workspace", "report")
        self.assertEqual(
            collector.get_tasks(), [(collector.collect_objects, (), {})]
        )

    @mock.patch.object(yaml, "dump")
    @mock.patch.object(
        kube, "get_object_by_kind", side_effect=Exception("Boom")
    )
    def test_collect_objects_exception(
        self, mock_get_obj_by_kind, mock_yaml_dump
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = k8s.K8sObjectsCollector(args, "/workspace", "repor")
        collector.objects = {
            "mynamespace": {
                "Job",
            },
        }
        with self.assertRaises(Exception):
            collector.collect_objects()
        self.mock_os_makedirs.assert_called_once_with(
            "/workspace/k8s/namespaced/mynamespace/job", exist_ok=True
        )
        mock_yaml_dump.assert_not_called()

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    @mock.patch.object(yaml, "dump")
    @mock.patch.object(kube, "get_object_by_kind", return_value=kube.Node)
    def test_collect_objects(
        self, mock_get_obj_by_kind, mock_yaml_dump, mock_open
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "trace",
            ]
        )
        collector = k8s.K8sObjectsCollector(args, "/workspace", "repor")
        collector.objects = {
            None: {
                "Node",
            },
        }
        self.mock_node_obj.return_value.filter.return_value = [self.mock_node]

        collector.collect_objects()
        self.mock_os_makedirs.assert_called_once_with(
            "/workspace/k8s/cluster/node", exist_ok=True
        )
        mock_yaml_dump.assert_called_once_with({"foo": "bar"}, mock.ANY)
