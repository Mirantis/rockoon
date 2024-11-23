#!/usr/bin/env python

import logging
import os
import sys

from openstack import resource
from openstack import connection

import pykube
import yaml

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(os.environ["HOSTNAME"])
LOG.setLevel("INFO")
CLOUD = connection.Connection(cloud=os.getenv("OS_CLOUD", "envvars"))


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config, timeout=30)
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


K8S_API = login()


class Service(resource.Resource):
    resource_key = "service"
    resources_key = "services"
    base_path = "/os-services"

    # capabilities
    allow_list = True
    allow_commit = True

    # Properties
    #: Status of service
    status = resource.Body("status")
    #: State of service
    state = resource.Body("state")
    #: Name of service
    binary = resource.Body("binary")
    #: Disabled reason of service
    disables_reason = resource.Body("disabled_reason")
    #: Host where service runs
    host = resource.Body("host")
    #: The availability zone of service
    availability_zone = resource.Body("zone")
    # The host is frozen or not. Only in cinder-volume service.
    frozen = resource.Body("frozen")
    # The date and time stamp when the extension was last updated.
    updated_at = resource.Body("updated_at")
    # The cluster name.
    cluster = resource.Body("cluster")
    # The volume service replication status.
    replication_status = resource.Body("replication_status")
    # The ID of active storage backend.
    active_backend_id = resource.Body("active_backend_id")
    # The state of storage backend. Only in cinder-volume service.
    backend_state = resource.Body("backend_state")


def get_pods_list(namespace, selector):
    pods = pykube.Pod.objects(K8S_API).filter(
        namespace=namespace,
        selector=selector,
    )
    return [pod for pod in pods]


def filter_hosts(expression, hosts):
    for host in hosts:
        if expression == host:
            hosts.remove(host)


def get_unknown_hosts(binary, pods, hosts_mapping, services_list):
    hosts = [s.host for s in services_list if s.binary == binary]
    if binary == "cinder-volume":
        for configured_host in hosts_mapping.keys():
            for backend in hosts_mapping[configured_host]:
                if configured_host == "<None>":
                    for pod in pods:
                        if pod.obj["spec"].get("hostNetwork"):
                            expected_host = f"{pod.obj['spec']['nodeName']}@{backend}"
                        else:
                            expected_host = f"{pod.name}@{backend}"
                        filter_hosts(expected_host, hosts)
                else:
                    filter_hosts(f"{configured_host}@{backend}", hosts)
    else:
        for pod in pods:
            # cinder-backup can be configured with hostnetworking
            if pod.obj["spec"].get("hostNetwork"):
                expected_host = pod.obj["spec"]["nodeName"]
            else:
                expected_host = pod.name
            filter_hosts(expected_host, hosts)
    if hosts:
        LOG.info(
            f"{binary}: Found hosts {hosts} that cannot exist according to current configuration"
        )
    return hosts


def get_down_services(excluded_hosts):
    slist = CLOUD.block_storage._list(Service)
    res = []
    for s in slist:
        if s.state == "down" and s.status == "enabled" and s.host not in excluded_hosts:
            res.append(s)
    return res


# Mask permissions to files 416 dirs 0750
os.umask(0o027)
excluded_hosts = os.environ["EXCLUDED_CINDER_HOSTS"].split(",")
LOG.info(f"Services with next hosts {excluded_hosts} are excluded from cleanup")

down_services = get_down_services(excluded_hosts)
cinder_service_components = ["backup", "scheduler", "volume"]
unknown_hosts_mapping = {}

with open("/tmp/hosts_mapping.yaml") as yaml_f:
    hosts_mapping = yaml.safe_load(yaml_f)

# Get all cinder hosts which cannot exist with current configuration
for component in cinder_service_components:
    binary = f"cinder-{component}"
    pods = get_pods_list(
        namespace="openstack",
        selector={"application": "cinder", "component": component},
    )
    if not pods:
        LOG.warning(
            f"No pods found for cinder {component} service, cannot make decision about cleanup"
        )
        continue
    unknown_hosts_mapping[binary] = get_unknown_hosts(
        binary, pods, hosts_mapping, down_services
    )

with open("/tmp/SERVICES_TO_CLEAN", "w") as f:
    lines = []
    for binary in unknown_hosts_mapping.keys():
        for host in unknown_hosts_mapping[binary]:
            service_str = f"{binary} {host}"
            LOG.info(f"Service {service_str} will be removed")
            lines.append(f"{service_str}\n")
    f.writelines(lines)
