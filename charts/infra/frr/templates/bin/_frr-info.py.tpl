#!/usr/bin/env python3

import base64
import ipaddress
import json
import logging
import netifaces as ni
import os
import socket
import sys

import pykube

FRR_BGP_NEIGHBOR_SECRET="frr-bgp-neighbors"
NAMESPACE=os.environ.get("NAMESPACE", "openstack")


log_level="DEBUG"
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("frr-info")

LOG.setLevel(log_level)


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(
        config=config, timeout=60
    )
    return client


api = login()
secret = {
  "metadata": {
    "labels": {
      "application": "frr",
    },
    "name": FRR_BGP_NEIGHBOR_SECRET,
    "namespace": NAMESPACE},
  "data": {}
}
obj = pykube.Secret(api, secret)
if not obj.exists():
    LOG.info(f"Creating secret {FRR_BGP_NEIGHBOR_SECRET}")
    pykube.Secret(api, secret).create()

source_ip = ni.ifaddresses(os.environ["BGP_UPDATE_SOURCE_INTERFACE"])[ni.AF_INET][0]['addr']

node_data = {
  "bgp": {
      "source_ip": source_ip
  }
}

data = {
    socket.gethostname(): base64.b64encode(json.dumps(node_data).encode()).decode()
}
LOG.info(f"Updating secret with: {node_data}")
obj.patch({"data": data})
LOG.info(f"Secret updated successfully")

