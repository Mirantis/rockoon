from unittest import mock
import logging


logging.basicConfig(level=logging.DEBUG)

# during layers import k8s config is parsed so a quick fix to avoid fail without config
# TODO(avolkov): make possibility to manage API client creation for tests
mock.patch("pykube.KubeConfig").start()
mock.patch("pykube.HTTPClient").start()
