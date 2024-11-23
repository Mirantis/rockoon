#!/usr/bin/env python3

import logging
import os
import sys
import time

import openstack
import pykube

_boolean_states = {'1': True, 'yes': True, 'true': True, 'on': True,
                   '0': False, 'no': False, 'false': False, 'off': False}


# In case if environment variable is set but contains an empty string,
# use the default instead of empty value
def get_var(name, default=''):
    value = os.environ.get(name) or None
    return value or default

def get_var_as_bool(name, default):
    value = get_var(name, '')
    return _boolean_states.get(value.lower(), default)

NODE_HOST_NAME = os.environ.get("NODE_HOST_NAME", "")
OCTAVIA_NAMESPACE = os.environ.get("OCTAVIA_NAMESPACE")
OCTAVIA_SETTINGS_CONFIGMAP = "octavia-settings"
OCTAVIA_WAIT_PORT_ACTIVE = get_var_as_bool("OCTAVIA_WAIT_PORT_ACTIVE", True)

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)

kube = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)
ost = openstack.connect()


def wait_port_active(port_id):
    if not port_id:
        raise Exception("No port to wait.")

    LOG.info("Waiting for port %s to become ACTIVE.", port_id)

    def is_port_ready():
        port_obj = ost.network.get_port(port_id)
        if port_obj.status != "ACTIVE":
            LOG.info("Port is not ready: %s", port_obj.to_dict())
            return False
        return True

    while not is_port_ready():
        time.sleep(2)

    LOG.info("Done. Port %s is ACTIVE.", port_id)


if OCTAVIA_WAIT_PORT_ACTIVE:
    port_configs = (
    pykube.ConfigMap.objects(kube)
    .filter(namespace=OCTAVIA_NAMESPACE)
    .get(name=OCTAVIA_SETTINGS_CONFIGMAP)
    .obj["data"]["ports_configs"]
)

    port_id = ""
    for port_conf in port_configs.split():
        if port_conf.startswith("PORT_ID_" + NODE_HOST_NAME.replace("-", "_")):
            port_id = port_conf.split("=")[1]
            break
    wait_port_active(port_id)
