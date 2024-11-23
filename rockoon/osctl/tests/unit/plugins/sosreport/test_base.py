import argparse
from unittest import mock

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl.plugins import constants
from rockoon import kube


class TestBaseLogsCollector(utils.BaseTestCase):
    def setUp(self):
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

    def test_report_all_hosts_all_components(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "report",
            ]
        )
        self.mock_node_obj.return_value = [self.mock_node]
        collector = base.BaseLogsCollector(args, "/workspace", "report")
        self.assertEqual("report", collector.mode)
        self.mock_node_obj.assert_called_once_with(self.mock_kube_client)
        self.assertEqual(
            {
                self.mock_node.name,
            },
            collector.hosts,
        )
        self.assertEqual(
            set(constants.OSCTL_COMPONENT_LOGGERS.keys()), collector.components
        )

    def test_report_host_component_nova(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--component",
                "nova",
                "--host",
                "custom-node-1",
                "report",
            ]
        )
        collector = base.BaseLogsCollector(args, "/workspace", "report")
        self.assertEqual("report", collector.mode)
        self.mock_node_obj.assert_not_called()
        self.assertEqual(
            {
                "custom-node-1",
            },
            collector.hosts,
        )
        self.assertEqual({"nova"}, collector.components)

    def test_report_host_labels_component_custom(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--component",
                "custom",
                "--host",
                "label=value",
                "report",
            ]
        )
        self.mock_node_obj.return_value.filter.return_value = [self.mock_node]
        collector = base.BaseLogsCollector(args, "/workspace", "report")
        self.assertEqual("report", collector.mode)
        self.mock_node_obj.assert_called_once_with(self.mock_kube_client)
        self.mock_node_obj.return_value.filter.assert_called_once_with(
            selector={"label": "value"}
        )
        self.assertEqual(
            {
                self.mock_node.name,
            },
            collector.hosts,
        )
        self.assertEqual({"custom"}, collector.components)
