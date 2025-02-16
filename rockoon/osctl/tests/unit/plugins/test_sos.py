import argparse
from unittest import mock
import os
import datetime

from rockoon.osctl.tests.unit import utils
from rockoon.osctl.plugins import sos


class TestSosBase(utils.BaseTestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(
            dest="subcommand", required=True
        )
        self.plugin = sos.SosReportShell(self.parser, self.subparsers)
        self.plugin.build_options()


class TestSosArgparse(TestSosBase):
    @property
    def ok_args(self):
        return [
            ["sos", "--all-components", "--all-hosts", "report"],
            ["sos", "--component", "nova", "--all-hosts", "report"],
            ["sos", "--component", "foo", "--all-hosts", "report"],
            # Optional arguments
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--elastic-url",
                "http://url:9200",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--elastic-username",
                "user",
                "--elastic-password",
                "pass",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--elastic-index-name",
                "index",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--elastic-query-size",
                "3",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--since",
                "3d",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--workers-number",
                "3",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--workspace",
                "/tmp",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--no-archive",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "elastic",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "nova",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "neutron",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "k8s",
                "report",
            ],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "elastic",
                "trace",
                "--message",
                "error",
            ],
        ]

    @property
    def not_ok_args(self):
        return [
            ["sos", "report"],
            ["sos", "--component", "elastic", "report"],
            ["sos", "--all-hosts", "report"],
            ["sos", "--host", "foo-host", "report"],
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "foo",
                "report",
            ],
        ]

    def test_load_ok(self):
        for args in self.ok_args:
            with self.subTest():
                self.parser.parse_args(args)

    def test_load_not_ok(self):
        for args in self.not_ok_args:
            with self.subTest():
                with self.assertRaises(SystemExit):
                    self.parser.parse_args(args)


@mock.patch("shutil.rmtree")
@mock.patch("shutil.make_archive")
@mock.patch.object(os, "makedirs")
class TestSosRun(TestSosBase):
    def setUp(self):
        super().setUp()
        self.elastic_task = (mock.Mock(), ("arg1",), {"kwarg1": "foo"})

        self.elastic_plugin = mock.Mock()
        self.elastic_plugin.get_tasks.return_value = [self.elastic_task]
        mock_plugin = mock.Mock(return_value=self.elastic_plugin)
        mock_registry = mock.patch(
            "rockoon.osctl.plugins.sosreport.registry",
            {"elastic": mock_plugin},
        )
        self.mock_registry = mock_registry.start()
        self.addCleanup(mock_registry.stop)

        self.mock_executor = mock.MagicMock()
        mock_tpe = mock.patch(
            "concurrent.futures.ThreadPoolExecutor", self.mock_executor
        )
        self.mock_tpe = mock_tpe.start()
        self.addCleanup(mock_tpe.stop)

        mock_tt = mock.patch("threading.Thread")
        self.mock_tt = mock_tt.start()
        self.addCleanup(mock_tt.stop)

        mock_futures = mock.patch("concurrent.futures.wait")
        self.mock_futures = mock_futures.start()
        self.addCleanup(mock_futures.stop)

        self.now = datetime.datetime(1986, 10, 8)
        mock_date = mock.patch(
            "rockoon.osctl.plugins.sos.datetime",
        )
        self.mock_date = mock_date.start()
        self.mock_date.utcnow.return_value = self.now
        self.addCleanup(mock_date.stop)

    def test_report_collector_can_run_false(
        self, mock_mkdirs, mock_shutil_make_archive, mock_shutil_rmtree
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "elastic",
                "report",
            ]
        )
        self.elastic_plugin.can_run = False
        self.plugin.report(args)
        mock_mkdirs.assert_called_with(
            f"/tmp/sosreport-{self.now.strftime('%Y%m%d%H%M%S')}",
            exist_ok=True,
        )
        self.elastic_plugin.get_tasks.assert_not_called()

    def test_report_collector_can_run(
        self, mock_mkdirs, mock_shutil_make_archive, mock_shutil_rmtree
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--collector",
                "elastic",
                "report",
            ]
        )
        self.elastic_plugin.can_run = True
        self.plugin.report(args)
        mock_mkdirs.assert_called_with(
            f"/tmp/sosreport-{self.now.strftime('%Y%m%d%H%M%S')}",
            exist_ok=True,
        )
        self.elastic_plugin.get_tasks.assert_called_once()
        self.mock_tt.return_value.start.assert_called_once()
        mock_shutil_make_archive.assert_called_once()
        mock_shutil_rmtree.assert_called_once()

    def test_report_collector_can_run_no_archive(
        self, mock_mkdirs, mock_shutil_make_archive, mock_shutil_rmtree
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--no-archive",
                "--collector",
                "elastic",
                "report",
            ]
        )
        self.elastic_plugin.can_run = True
        self.plugin.report(args)
        mock_mkdirs.assert_called_with(
            f"/tmp/sosreport-{self.now.strftime('%Y%m%d%H%M%S')}",
            exist_ok=True,
        )
        self.elastic_plugin.get_tasks.assert_called_once()
        self.mock_tt.return_value.start.assert_called_once()
        mock_shutil_make_archive.assert_not_called()
        mock_shutil_rmtree.assert_not_called()

    def test_report_collector_can_run_max_workers(
        self, mock_mkdirs, mock_shutil_make_archive, mock_shutil_rmtree
    ):
        args = self.parser.parse_args(
            [
                "sos",
                "--all-components",
                "--all-hosts",
                "--workers-number",
                "10",
                "--collector",
                "elastic",
                "report",
            ]
        )
        self.elastic_plugin.can_run = True
        self.plugin.report(args)
        mock_mkdirs.assert_called_with(
            f"/tmp/sosreport-{self.now.strftime('%Y%m%d%H%M%S')}",
            exist_ok=True,
        )
        self.elastic_plugin.get_tasks.assert_called_once()
        self.mock_tt.return_value.start.assert_called_once()
        self.mock_tpe.assert_called_once_with(max_workers=10)
