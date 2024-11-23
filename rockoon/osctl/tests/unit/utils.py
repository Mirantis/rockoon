import os

from unittest import TestCase
from unittest import mock


class BaseTestCase(TestCase):
    def setUp(self):
        mock_os_makedirs = mock.patch.object(os, "makedirs")
        self.mock_os_makedirs = mock_os_makedirs.start()
        self.addCleanup(mock_os_makedirs.stop)
