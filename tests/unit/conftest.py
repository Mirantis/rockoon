#    Copyright 2020 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import asyncio
import logging
from unittest import mock

import pykube

from rockoon import kube
from rockoon import layers
from rockoon import resource_view

import pytest
import yaml

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


# TODO(vdrok): Remove with switch to python3.8 as mock itself will be able
#              to handle async
class AsyncMock(mock.Mock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


@pytest.fixture
def dashboard_policy_default():
    yield yaml.safe_load(open("tests/fixtures/dashboard_policy_default.yaml"))


@pytest.fixture
def openstackdeployment(mocker):
    osdpl_mspec = mocker.patch(
        "rockoon.kube.OpenStackDeployment.mspec",
        new_callable=mock.PropertyMock,
    )
    osdpl_mspec.return_value = render_mspec()
    yield yaml.safe_load(open("tests/fixtures/openstackdeployment.yaml"))
    mocker.stopall()


@pytest.fixture
def artifacts_cm():
    yield yaml.safe_load(open("tests/fixtures/artifacts_cm.yaml"))


def render_mspec():
    osdpl = yaml.safe_load(open("tests/fixtures/openstackdeployment.yaml"))
    mspec = layers.merge_spec(osdpl["spec"], LOG)
    return mspec


@pytest.fixture
def openstackdeployment_mspec():
    return render_mspec()


@pytest.fixture
def mock_kube_get_osdpl(mocker, fake_osdpl):
    osdpl = mocker.patch("rockoon.kube.get_osdpl")
    osdpl.return_value = fake_osdpl
    yield osdpl
    mocker.stopall()


@pytest.fixture
def mock_kube_artifacts_configmap(mocker, fake_artifacts_configmap):
    artifacts_cm = mocker.patch("rockoon.kube.artifacts_configmap")
    artifacts_cm.return_value = fake_artifacts_configmap
    yield artifacts_cm
    mocker.stopall()


@pytest.fixture
def common_template_args():
    yield yaml.safe_load(
        open(
            "tests/fixtures/render_service_template/input/common_template_args.yaml"
        )
    )


def _osdpl_minimal(os_release):
    return {
        "openstack_version": os_release,
        "size": "tiny",
        "preset": "compute",
    }


def _osdpl_mspec(os_release):
    osdpl = _osdpl_minimal(os_release)
    mspec = layers.merge_spec(osdpl, LOG)
    return mspec


@pytest.fixture
def osdpl_min_train():
    return _osdpl_mspec("train")


@pytest.fixture
def osdpl_min_stein():
    return _osdpl_mspec("stein")


@pytest.fixture
def osdpl_min_rocky():
    return _osdpl_mspec("rocky")


@pytest.fixture
def compute_helmbundle():
    yield yaml.safe_load(open("tests/fixtures/compute_helmbundle.yaml"))


@pytest.fixture
def compute_helmbundle_all():
    yield yaml.safe_load(open("tests/fixtures/compute_helmbundle_all.yaml"))


@pytest.fixture
def kopf_adopt(mocker):
    mock_adopt = mocker.patch("kopf.adopt")
    yield mock_adopt
    mocker.stopall()


@pytest.fixture
def kube_resource_list(mocker):
    mock_reslist = mocker.patch("rockoon.kube.resource_list")
    yield mock_reslist
    mocker.stopall()


@pytest.fixture
def kube_resource(mocker):
    mock_res = mocker.patch("rockoon.kube.resource")
    yield mock_res
    mocker.stopall()


@pytest.fixture
def asyncio_wait_for_timeout(mocker):
    async def mock_wait(f, timeout):
        await f
        raise asyncio.TimeoutError()

    mocker.patch("rockoon.utils.async_retry", AsyncMock())
    mock_wait = mocker.patch.object(asyncio, "wait_for", mock_wait)
    yield mock_wait
    mocker.stopall()


@pytest.fixture
def openstack_connect(mocker):
    mock_connect = mocker.patch("openstack.connect")
    yield mock_connect
    mocker.stopall()


@pytest.fixture
def override_setting(request, mocker):
    print(mocker, request.param)
    setting_mock = mocker.patch(
        f"rockoon.settings.{request.param['name']}",
        request.param["value"],
    )
    yield setting_mock
    mocker.stopall()


@pytest.fixture
def fake_osdpl(openstackdeployment):
    osdpl = kube.OpenStackDeployment(kube.kube_client(), openstackdeployment)
    yield osdpl


@pytest.fixture
def fake_artifacts_configmap(artifacts_cm):
    res = pykube.ConfigMap(kube.kube_client(), artifacts_cm)
    yield res


@pytest.fixture
def load_fixture():
    def loader(name):
        return yaml.safe_load(open("tests/fixtures/" + name))

    yield loader


@pytest.fixture
def helm_error_1_item():
    fixture_file = "tests/fixtures/test_helm/1_item.txt"
    with open(fixture_file, "rb") as f:
        error = f.read()
    yield error


@pytest.fixture
def helm_error_5_item():
    fixture_file = "tests/fixtures/test_helm/5_item.txt"
    with open(fixture_file, "rb") as f:
        error = f.read()
    yield error


@pytest.fixture
def helm_error_forbidden_item():
    fixture_file = "tests/fixtures/test_helm/forbidden_item.txt"
    with open(fixture_file, "rb") as f:
        error = f.read()
    yield error


@pytest.fixture
def helm_error_rollout_restart():
    fixture_file = "tests/fixtures/test_helm/rollout_restart.txt"
    with open(fixture_file, "rb") as f:
        error = f.read()
    yield error


@pytest.fixture
def substitute_mock(mocker):
    substitute_mock = mocker.patch(
        "rockoon.layers.substitude_osdpl",
    )
    yield substitute_mock
    mocker.stopall()


@pytest.fixture
def helm_error_pvc_test():
    fixture_file = "tests/fixtures/test_helm/pvc_test.txt"
    with open(fixture_file, "rb") as f:
        error = f.read()
    yield error


@pytest.fixture(scope="session")
def child_view():
    mspec = render_mspec()
    return resource_view.ChildObjectView(mspec)


@pytest.fixture
def node(mocker):
    node = mocker.patch("rockoon.kube.Node")
    node.return_value = mock.MagicMock()
    node.return_value.name = "fake-node"
    yield node.return_value
    mocker.stopall()


@pytest.fixture
def safe_node(mocker):
    node = mocker.patch("rockoon.kube.safe_get_node")
    node.return_value = mock.MagicMock()
    node.return_value.name = "fake-node"
    yield node.return_value
    mocker.stopall()


@pytest.fixture
def nwl(mocker):
    nwl = mocker.patch("rockoon.maintenance.NodeWorkloadLock.get_by_node")
    nwl.reteurn_value = mock.Mock()
    yield nwl
    mocker.stopall()


@pytest.fixture
def socket(mocker):
    nwl = mocker.patch("socket.socket")
    nwl.reteurn_value = mock.Mock()
    yield nwl
    mocker.stopall()


@pytest.fixture
def federation_provider():
    yield {
        "issuer": "https://keycloak.it.just.works/auth/realms/iam",
        "description": "Good provider",
        "mapping": [
            {
                "local": [
                    {"user": {"email": "{1}", "name": "{0}"}},
                    {"domain": {"name": "Default"}, "groups": "{2}"},
                ],
                "remote": [
                    {"type": "OIDC-iam_username"},
                    {"type": "OIDC-email"},
                    {"type": "OIDC-iam_roles"},
                ],
            }
        ],
        "metadata": {
            "client": {"client_id": "os"},
            "conf": {
                "response_type": "id_token",
                "scope": "openid email profile",
                "ssl_validate_server": False,
            },
            "provider": {
                "value_from": {
                    "from_url": {
                        "url": "https://keycloak.it.just.works/auth/realms/iam/.well-known/openid-configuration"
                    }
                }
            },
        },
    }
