import argparse
from unittest import mock

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos
from rockoon.osctl.plugins.sosreport import elastic


class TestK8sElasticLogsCollector(utils.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(
            dest="subcommand", required=True
        )
        self.plugin = sos.SosReportShell(self.parser, self.subparsers)
        self.plugin.build_options()

        pod_patcher = mock.patch("rockoon.kube.Pod")
        self.mock_pod = pod_patcher.start()
        self.mock_pod.name = "libvirt-1"
        self.addCleanup(pod_patcher.stop)

        mock_opensearch_client = mock.patch.object(elastic, "OpenSearch")
        mock_opensearch_patcher = mock_opensearch_client.start()
        self.mock_opensearch_client = mock_opensearch_patcher.return_value
        self.addCleanup(mock_opensearch_client.stop)

        mock_dump_exec_result = mock.patch(
            "rockoon.osctl.plugins.sosreport.base.BaseLogsCollector.dump_exec_result"
        )
        self.mock_dump_exec_result = mock_dump_exec_result.start()
        self.addCleanup(mock_dump_exec_result.stop)
        self.default_args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "custom",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        mock_log = mock.patch.object(elastic, "LOG")
        self.mock_log = mock_log.start()
        self.addCleanup(mock_log.stop)

    def _get_hits(self):
        return [
            {
                "_source": {
                    "@timestamp": "TIMESTAMP",
                    "log": {"level": "SEVERITY"},
                    "message": "MESSAGE1",
                    "orchestrator": {
                        "pod": "POD_NAME",
                        "namespace": "openstack",
                        "type": "kubernetes",
                        "labels": {"label": "value"},
                    },
                    "host": {"hostname": "HOST"},
                    "container": {
                        "name": "CONTAINER_NAME",
                    },
                }
            },
            {
                "_source": {
                    "@timestamp": "TIMESTAMP",
                    "log": {"level": "SEVERITY"},
                    "message": "MESSAGE2",
                },
                "sort": "123",
            },
        ]

    def test_get_tasks_logger_nova(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "nova",
                "report",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "report")
        self.assertCountEqual(
            collector.get_tasks(),
            [
                (
                    collector.collect_logs,
                    ("nova",),
                    {
                        "host": "host-1",
                        "between": "now-1w,now",
                        "message": None,
                    },
                ),
                (
                    collector.collect_logs,
                    ("libvirt",),
                    {
                        "host": "host-1",
                        "between": "now-1w,now",
                        "message": None,
                    },
                ),
            ],
        )

    def test_get_tasks_logger_nova_between(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--between",
                "2024-08-12T10:00:00,2024-08-12T11:00:00",
                "--component",
                "nova",
                "report",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "report")
        self.assertCountEqual(
            collector.get_tasks(),
            [
                (
                    collector.collect_logs,
                    ("nova",),
                    {
                        "host": "host-1",
                        "between": "2024-08-12T10:00:00,2024-08-12T11:00:00",
                        "message": None,
                    },
                ),
                (
                    collector.collect_logs,
                    ("libvirt",),
                    {
                        "host": "host-1",
                        "between": "2024-08-12T10:00:00,2024-08-12T11:00:00",
                        "message": None,
                    },
                ),
            ],
        )

    def test_get_tasks_logger_custom_message(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "custom",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "trace")
        self.assertCountEqual(
            collector.get_tasks(),
            [
                (
                    collector.collect_logs,
                    ("custom",),
                    {
                        "host": "host-1",
                        "between": "now-1d,now",
                        "message": "error",
                    },
                ),
            ],
        )

    def test_get_hosts_all_hosts(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-hosts",
                "--component",
                "custom",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "trace")
        res = collector.get_hosts()
        self.assertCountEqual([None], res)

    def test_get_hosts_exact_hosts(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "custom",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "trace")
        res = collector.get_hosts()
        self.assertCountEqual(["host-1"], res)

    def test_get_loggers_known(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "nova",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "trace")
        res = collector.get_loggers(["nova"])
        self.assertCountEqual(["nova", "libvirt"], res)

    def test_get_loggers_not_known(self):
        args = self.parser.parse_args(
            [
                "sos",
                "--host",
                "host-1",
                "--component",
                "custom",
                "--since",
                "1d",
                "trace",
                "--message",
                "error",
            ]
        )
        collector = elastic.ElasticLogsCollector(args, "/workspace", "trace")
        res = collector.get_loggers(["custom"])
        self.assertCountEqual(["custom"], res)

    def test_query_logger(self):
        collector = elastic.ElasticLogsCollector(
            self.default_args, "/workspace", "trace"
        )
        res = collector.query_logger("logger")
        expected = {
            "bool": {
                "should": [
                    {
                        "simple_query_string": {
                            "fields": ["event.provider"],
                            "query": f"logger*",
                        }
                    }
                ],
                "minimum_should_match": 1,
            }
        }
        self.assertEqual(expected, res)

    def test_query_message(self):
        collector = elastic.ElasticLogsCollector(
            self.default_args, "/workspace", "trace"
        )
        res = collector.query_message("error")
        expected = {
            "bool": {
                "should": [{"match_phrase": {"message": "error"}}],
                "minimum_should_match": 1,
            }
        }
        self.assertEqual(expected, res)

    def test_query_host(self):
        collector = elastic.ElasticLogsCollector(
            self.default_args, "/workspace", "trace"
        )
        res = collector.query_host("host-1")
        expected = {
            "bool": {
                "should": [{"match_phrase": {"host.hostname": "host-1"}}],
                "minimum_should_match": 1,
            }
        }
        self.assertEqual(expected, res)

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_collect_logs_all_hosts_no_search_after(self, mock_open):
        collector = elastic.ElasticLogsCollector(
            self.default_args, "/workspace", "trace"
        )
        self.mock_opensearch_client.search.side_effect = [
            {"hits": {"hits": self._get_hits()}},
            {"hits": {"hits": []}},
        ]
        collector.collect_logs(
            "logger", host=None, message=None, between="now-1w,now"
        )
        self.mock_log.info.assert_has_calls(
            [mock.call("Starting logs collection for all hosts logger")],
            any_order=True,
        )
        mock_open.return_value.write.assert_has_calls(
            [mock.call("TIMESTAMP SEVERITY MESSAGE1")], any_order=True
        )
        self.mock_os_makedirs.assert_called_once()
        self.assertEqual(2, self.mock_opensearch_client.search.call_count)

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_collect_logs_all_hosts_search_after(self, mock_open):
        collector = elastic.ElasticLogsCollector(
            self.default_args, "/workspace", "trace"
        )
        self.mock_opensearch_client.search.side_effect = [
            {"hits": {"hits": self._get_hits()}},
            {"hits": {"hits": self._get_hits()}},
            {"hits": {"hits": []}},
        ]
        collector.collect_logs(
            "logger", host=None, message=None, between="now-1w,now"
        )
        self.mock_log.info.assert_has_calls(
            [mock.call("Starting logs collection for all hosts logger")],
            any_order=True,
        )
        mock_open.return_value.write.assert_has_calls(
            [mock.call("TIMESTAMP SEVERITY MESSAGE1")], any_order=True
        )
        self.assertEqual(2, self.mock_os_makedirs.call_count)
        self.assertEqual(3, self.mock_opensearch_client.search.call_count)
