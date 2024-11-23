#!/usr/bin/env python3

import logging
import os
import sys

import openstack
from openstack.compute.v2 import service as _service

import pykube
from retry import retry


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

LOG = logging.getLogger(__name__)


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config, timeout=30)
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def get_down_services(excluded=[]):
    LOG.info("Searching for down services")
    res = [
        s
        for s in ost.compute.services()
        if s.binary not in excluded and s.state == "down" and s.status == "enabled"
    ]
    if res:
        LOG.info(f"Found down services {res}")
    return res


@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def get_pod(name, namespace):
    LOG.info(f"Finding pod {namespace}/{name}")
    return pykube.Pod.objects(k8s).filter(namespace=namespace).get_or_none(name=name)


@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def delete_service(s):
    LOG.info(f"Deleting service {s.host} {s.binary}")
    ost.compute._delete(_service.Service, s.id)


k8s = login()

OS_CLOUD = os.getenv("OS_CLOUD_SYSTEM", "envvars")
ost = openstack.connect(cloud=OS_CLOUD)

namespace = os.getenv("NAMESPACE", "openstack")
down_services = get_down_services(excluded=["nova-compute"])
if not down_services:
    LOG.info(f"Nothing to clean, all services are up")
    sys.exit(0)
# Remove only services which have no existing pods,
# some services can be down because they just cannot connect to rabbit or database
for s in down_services:
    if get_pod(s.host, namespace):
        LOG.info(
            f"Service {s.binary} on host {s.host} is down, but pod still exists, not removing service"
        )
    else:
        delete_service(s)
