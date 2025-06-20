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
import configparser
import os
import glob
import random
import sys
import signal
import time
import faulthandler

import json
import kopf
from kopf._core.engines.posting import event_queue_var
from pathlib import Path

from rockoon import constants as const
from rockoon.utils import get_logger


faulthandler.register(signal.SIGHUP, all_threads=True)
faulthandler.enable(file=sys.stderr, all_threads=True)

HEARTBEAT = time.time()
CURRENT_NUMBER_OF_TASKS = -1
LOG = get_logger(__name__)


def bool_from_env(env_name, default):
    """Convert env variable into boolean
    :param env_name: the name of environment variable
    :param default: the default value to return
    :returns True: when value of env is in TRUE_STRINGS
    :returns False: when value of env is in FALSE_STRINGS
    :raise kopf.PermanentError: when value not in TRUE_STRINGS or FALSE_STRINGS
    """

    data = os.environ.get(env_name)

    if data is None:
        return default

    lowered = data.strip().lower()

    if lowered in const.TRUE_STRINGS:
        return True
    elif lowered in const.FALSE_STRINGS:
        return False

    raise kopf.PermanentError(f"Failed to convert {data} into boolean.")


def json_from_env(env_name, default):
    """Load a json string from an env variable

    :param env_name: the name of environment variable
    :param default: the default value to return
    :returns True: when value of env is in TRUE_STRINGS
    :returns False: when value of env is in FALSE_STRINGS
    :raise kopf.PermanentError: when value not in TRUE_STRINGS or FALSE_STRINGS

    """
    data = os.environ.get(env_name)

    if data is None:
        return default

    return json.loads(data)


class Config(configparser.ConfigParser):
    def __init__(self, *args, **kwargs):
        self.file_cache = {}
        self.conf_dir = "/etc/rockoon"
        self.filenames = self.get_config_files()
        super().__init__(self, *args, **kwargs)

    def __getitem__(self, item):
        self.read_config()
        return super().__getitem__(item)

    def _get(self, section, conv, option, **kwargs):
        self.read_config()
        return super()._get(section, conv, option, **kwargs)

    def get_config_files(self):
        res = []
        for path in [
            os.path.join(
                sys.prefix,
                "etc/rockoon",
            ),
            self.conf_dir,
            f"{self.conf_dir}/conf.d",
        ]:
            if os.path.isdir(path):
                for cfg in glob.glob(f"{path}/*.ini"):
                    res.append(cfg)
        return res

    def read_config(self):
        reloaded = True
        for conf_file in self.filenames:
            mtime = os.path.getmtime(conf_file)
            if mtime > self.file_cache.get("mtime", 0):
                reloaded = False
                self.file_cache["mtime"] = mtime
                break
        if not reloaded:
            LOG.info("Reloading configuration.")
            self.read(self.filenames)

    def getString(self, section, option):
        return self.get(section, option).strip('"')


# The name of openstack deployment namespace
OSCTL_OS_DEPLOYMENT_NAMESPACE = os.environ.get(
    "OSCTL_OS_DEPLOYMENT_NAMESPACE", "openstack"
)

# The name of os controller deployment namespace
OSCTL_CONTROLLER_NAMESPACE = os.environ.get(
    "OSCTL_CONTROLLER_NAMESPACE", "osh-system"
)

# The name of openstack deployment namespace
OSCTL_CEPH_SHARED_NAMESPACE = os.environ.get(
    "OSCTL_CEPH_SHARED_NAMESPACE", "openstack-ceph-shared"
)

# The location of clouds.yaml with admin credentials
OS_CLIENT_CONFIG_FILE = os.environ.get(
    "OS_CLIENT_CONFIG_FILE", "/etc/openstack/clouds.yaml"
)

# The name of cloud in clouds.yaml
OS_CLOUD = os.environ.get("OS_CLOUD", "osctl")
OS_CLOUD_SYSTEM = os.environ.get("OS_CLOUD_SYSTEM", f"{OS_CLOUD}-system")

# TODO(mkarpin): move openstack related settings to separate file
# as settings.py is imported inside kube.py
# Url for openstack binaries/helm charts
OSCTL_BINARY_BASE_URL = os.environ.get("OSCTL_BINARY_BASE_URL", "")
# Url for openstack docker images
OSCTL_IMAGES_BASE_URL = os.environ.get("OSCTL_IMAGES_BASE_URL", "")

# The name of secret with BGP information
OSCTL_BGPVPN_NEIGHBOR_INFO_SECRET_NAME = os.environ.get(
    "OSCTL_BGPVPN_BGP_NEIGHBOR_INFO_SECRET_NAME", "frr-bgp-neighbors"
)

# The number of retries while waiting a resouce deleted
OSCTL_RESOURCE_DELETED_WAIT_RETRIES = int(
    os.environ.get("OSCTL_RESOURCE_DELETED_WAIT_RETRIES", 120)
)

# The number of seconds to sleep while waiting a resouce deleted
OSCTL_RESOURCE_DELETED_WAIT_TIMEOUT = int(
    os.environ.get("OSCTL_RESOURCE_DELETED_WAIT_TIMEOUT", 1)
)

OSCTL_REDIS_NAMESPACE = os.environ.get(
    "OSCTL_REDIS_NAMESPACE", "openstack-redis"
)

OSCTL_HEARTBEAT_INTERVAL = int(os.environ.get("OSCTL_HEARTBEAT_INTERVAL", 300))

OSCTL_HEARTBEAT_MAX_DELAY = int(
    os.environ.get("OSCTL_HEARTBEAT_MAX_DELAY", OSCTL_HEARTBEAT_INTERVAL * 3)
)

# If we did not start applying change in OSCTL_APPLYING_MAX_DELAY seconds
# controller will be restarted
OSCTL_APPLYING_MAX_DELAY = int(
    os.environ.get("OSCTL_APPLYING_MAX_DELAY", "60")
)

OSCTL_BATCH_HEATH_UPDATER_PERIOD = int(
    os.environ.get("OSCTL_BATCH_HEATH_UPDATER_PERIOD", 60)
)

OSCTL_PYKUBE_HTTP_REQUEST_TIMEOUT = float(
    os.environ.get("OSCTL_PYKUBE_HTTP_REQUEST_TIMEOUT", 60)
)

OSCTL_MAX_TASKS = int(os.environ.get("OSCTL_MAX_TASKS", 150))

OSCTL_HEARTBEAT_PEERING_OBJECT_NAME = os.environ.get(
    "OSCTL_HEARTBEAT_PEERING_OBJECT_NAME", "rockoon.osdpl"
)

if OSCTL_HEARTBEAT_INTERVAL:

    @kopf.timer(
        "zalando.org",
        "v1",
        "kopfpeerings",
        interval=OSCTL_HEARTBEAT_INTERVAL,
        when=lambda name, **_: OSCTL_HEARTBEAT_PEERING_OBJECT_NAME == name,
    )
    def heartbeat(spec, **kwargs):
        global HEARTBEAT
        global CURRENT_NUMBER_OF_TASKS
        HEARTBEAT = time.time()
        CURRENT_NUMBER_OF_TASKS = event_queue_var.get().qsize()


# The version of curren cluster release, example 8.4.0-rc+22.1
OSCTL_CLUSTER_RELEASE = os.environ.get("OSCTL_CLUSTER_RELEASE", "")


# A dict of OpenStack node labels per role in json format.
# See the structure below
# If a node has one of specified labels with the matching value,
# an appropriate NodeWorkloadLock object will be created.
def _parse_node_roles_from_env():
    roles = json_from_env(
        "OSCTL_OPENSTACK_NODE_LABELS",
        {
            "controller": {"openstack-control-plane": "enabled"},
            "compute": {"openstack-compute-node": "enabled"},
            "gateway": {"openstack-gateway": "enabled"},
        },
    )

    parsed_roles = {const.NodeRole[k]: v for k, v in roles.items()}
    for d in parsed_roles.values():
        if len(d.keys()) != 1:
            raise kopf.PermanentError(
                "OSCTL_OPENSTACK_NODE_LABELS expect 1 label key"
            )
    return parsed_roles


try:
    OSCTL_OPENSTACK_NODE_LABELS = _parse_node_roles_from_env()
except Exception as exc:
    # may raise KeyError from Enum, AttributeError from non-dict items()
    # and whatever from json.load
    raise kopf.PermanentError(
        f"OSCTL_OPENSTACK_NODE_LABELS invalid format - {exc}"
    )


def _get_internal_labels():

    int_labels = {}
    for role_name, role_labels in OSCTL_OPENSTACK_NODE_LABELS.items():
        for label_name in role_labels.keys():
            int_labels[role_name] = {f"rockoon-{label_name}": "controller"}
    return int_labels


OSCTL_OPENSTACK_NODE_LABELS_INTERNAL = _get_internal_labels()

# The dict defining proxy settings
OSCTL_PROXY_DATA = json_from_env("OSCTL_PROXY_DATA", {"enabled": False})
OSCTL_PROXY_SECRET_NAMESPACE = os.environ.get(
    "OSCTL_PROXY_SECRET_NAMESPACE", "osh-system"
)
OSCTL_CDN_CA_BUNDLE_DATA = json_from_env("OSCTL_CDN_CA_BUNDLE_DATA", {})
OSCTL_CDN_CA_BUNDLE_SECRET_NAMESPACE = os.environ.get(
    "OSCTL_CDN_CA_BUNDLE_SECRET_NAMESPACE", "openstack"
)
OSCTL_CEPH_DEPLOYMENT_NAMESPACE = os.environ.get(
    "OSCTL_CEPH_DEPLOYMENT_NAMESPACE", "rook-ceph"
)
OSCTL_LMA_DEPLOYMENT_NAMESPACE = os.environ.get(
    "OSCTL_LMA_DEPLOYMENT_NAMESPACE", "stacklight"
)
OSCTL_TF_DEPLOYMENT_NAMESPACE = os.environ.get(
    "OSCTL_TF_DEPLOYMENT_NAMESPACE", "tf"
)


# The dict defining IAM data {"client": "os", "enabled": True, "oidcCASecret": "oidc-cert", url: "https://1.2.3.4"}
OSDPL_IAM_DATA = json_from_env("OSDPL_IAM_DATA", {"enabled": False})

# List with pod networks data [{"cidr": "1.2.3.0/24"}]
OSCTL_POD_NETWORKS_DATA = json_from_env(
    "OSCTL_POD_NETWORKS_DATA", [{"cidr": "192.168.0.0/16"}]
)

CONF = Config()


class InfiniteBackoffsWithJitter:
    def __iter__(self):
        while True:
            yield 10 + random.randint(-5, +5)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.watching.connect_timeout = 1 * 60
    # NOTE(vsaienko): The watching.server_timeout is used to set timeoutSeconds
    # for kubernetes watching request.
    # Timeout for the list/watch call. This limits the duration of the call,
    # regardless of any activity or inactivity.
    # IMPORTANT: this timeout have to be less than aiohttp client.timeout
    settings.watching.server_timeout = os.environ.get(
        "KOPF_WATCH_STREAM_TIMEOUT", 1 * 300
    )
    # Defines total timeout for aiohttp watching session.
    settings.watching.client_timeout = 1 * 600
    # setting unique finalizer name for each controller
    settings.persistence.finalizer = (
        f"lcm.mirantis.com/{OSCTL_HEARTBEAT_PEERING_OBJECT_NAME}-finalizer"
    )
    settings.networking.error_backoffs = InfiniteBackoffsWithJitter()
    settings.execution.max_workers = CONF.getint("osctl", "max_workers")


# HELM SETTINGS
HOME = str(Path.home())
HELM_REPOSITORY_CACHE = os.environ.get(
    "HELM_REPOSITORY_CACHE", os.path.join(HOME, ".cache/helm/repository")
)
HELM_CHARTS_DIR = os.environ.get("HELM_CHARTS_DIR", "/opt/operator/charts/")
# END HELM SETTINGS
