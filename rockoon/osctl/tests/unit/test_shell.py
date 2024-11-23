import argparse
from unittest import mock

from rockoon.osctl.tests.unit import utils
from rockoon.osctl import shell
from rockoon.osctl import plugins


class TestShell(utils.BaseTestCase):
    def setUp(self):
        self.mock_plugin = mock.Mock()
        mock_plugin = mock.Mock(return_value=self.mock_plugin)
        mock_registry = mock.patch(
            "rockoon.osctl.plugins.registry",
            {"mock_plugin": mock_plugin},
        )
        self.mock_registry = mock_registry.start()
        self.addCleanup(mock_registry.stop)

    @mock.patch.object(
        argparse.ArgumentParser, "add_subparsers", autospec=True
    )
    def test_load_plugins_instances(self, mock_add_subparsers):
        client = shell.Osctl()
        expected = plugins.registry.keys()
        actual = client.plugins.keys()
        self.assertEqual(actual, expected)

    def test_load_plugins_calls(self):
        shell.Osctl()
        self.mock_plugin.build_options.assert_called_once()

    @mock.patch("argparse.ArgumentParser", autospeec=True)
    def test_run(self, mock_parser):
        mock_parser.return_value.parse_args.return_value.subcommand = (
            "mock_plugin"
        )
        client = shell.Osctl()
        client.run()
        self.mock_plugin.run.assert_called_once()
