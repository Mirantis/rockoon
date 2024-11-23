#!/usr/bin/env python3

import hashlib
import logging
import openstack
import os
import pykube
import requests
import ujson as json
import shutil
import sys
import time
from retry import retry

_boolean_states = {'1': True, 'yes': True, 'true': True, 'on': True,
                   '0': False, 'no': False, 'false': False, 'off': False}


# In case if environment variable is set but contains an empty string,
# use the default instead of empty value
def get_var(name, default=''):
    value = os.environ.get(name) or None
    return value or default


def get_var_as_bool(name, default):
    value = get_var(name, '')
    if isinstance(default, str):
        default = _boolean_states.get(default.lower(), default)
        if isinstance(default, str):
            raise Exception(f"default for '{name}' contains some non-binary trash: '{default}'")
    return _boolean_states.get(value.lower(), default)

OCTAVIA_OSH_LB_SUBNETS = get_var("OCTAVIA_OSH_LB_SUBNETS")
OCTAVIA_OSH_LB_HM_REMOTE_PORT = get_var("OCTAVIA_OSH_LB_HM_REMOTE_PORT")
OCTAVIA_OSH_LB_HM_HOST_PORT = get_var("OCTAVIA_OSH_LB_HM_HOST_PORT")
OCTAVIA_NODE_SELECTOR = get_var("OCTAVIA_NODE_SELECTOR")
OCTAVIA_NAMESPACE = get_var("OCTAVIA_NAMESPACE")
OCTAVIA_MGMT_NET = get_var("OCTAVIA_MANAGEMENT_NETWORK_NAME")
OCTAVIA_MGMT_SUBNET_PREFIX = "lb-mgmt-subnet-"
OCTAVIA_PORT_PREFIX = "octavia-health-manager-listen-port-"
OCTAVIA_SECGROUP_MGMT = "lb-mgmt-sec-grp"
OCTAVIA_SECGROUP_HEALTH_MANAGER = "lb-health-mgr-sec-grp"
OCTAVIA_FLAVOR = "m1.amphora"
OCTAVIA_SETTINGS_CONFIGMAP = "octavia-settings"
OCTAVIA_WAIT_NEUTRON_RESOURCES = get_var_as_bool("OCTAVIA_WAIT_NEUTRON_RESOURCES", True)
OCTAVIA_MGMT_CREATE_PORTS = get_var_as_bool("OCTAVIA_MGMT_CREATE_PORTS", True)


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


def log_info(func):
    def wrapper(*args, **kwargs):
        LOG.info("Applying %s ...", args[1].__name__)
        result = func(*args, **kwargs)
        LOG.info("  Done [%s=%s]", result.name, result.id)
        return result

    return wrapper


@log_info
@retry(openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG)
def ensure_openstack_resource(find, create, attrs):
    return find(attrs["name"]) or create(**attrs)


@retry(openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG)
def create_security_group_rule(**attrs):
    LOG.info("Applying create_security_group_rule ...")
    try:
        secgroup_rule = ost.network.create_security_group_rule(**attrs)
    except openstack.exceptions.ConflictException as exc:
        LOG.info("  Done[id=%s]", str(exc).split()[-1][:-1])
    else:
        LOG.info("  Done [%s=%s]", secgroup_rule.protocol, secgroup_rule.id)


@retry(openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG)
def set_quotas(attrs):
    ost_system.set_network_quotas(ost.current_project_id, **attrs["network"])
    ost_system.set_compute_quotas(ost.current_project_id, **attrs["compute"])


@retry(exceptions=Exception, delay=5, tries=-1, backoff=1, logger=LOG)
def wait_neutron_resources(namespace):
    LOG.info("Waiting for neutron resources.")
    LOG.info("Waiting for dhcp agents.")
    while True:
        dhcp_pods = pykube.Pod.objects(kube).filter(
            namespace=namespace,
            selector={"application": "neutron", "component": "dhcp-agent"},
        )
        dhcp_pods_status = [pod.ready for pod in dhcp_pods]
        if dhcp_pods_status and all(dhcp_pods_status):
            LOG.info("All dhcp pods are ready")
            break
        time.sleep(5)
    octavia_hosts = [
        node.name
        for node in pykube.Node.objects(kube).filter(
            selector=dict([OCTAVIA_NODE_SELECTOR.split("=")])
        )
    ]
    ready_hosts = []
    LOG.info("Waiting for neutron ovs agents.")
    while set(octavia_hosts) - set(ready_hosts):
        time.sleep(5)
        ovs_pods = pykube.Pod.objects(kube).filter(
            namespace=namespace,
            selector={"application": "neutron", "component": "neutron-ovs-agent"},
        )
        ready_hosts = [
            pod.obj["spec"]["nodeName"]
            for pod in ovs_pods
            if pod.obj["status"]["phase"] == "Running"
        ]
    LOG.info(f"All neutron-ovs-agent pods on {OCTAVIA_NODE_SELECTOR} are ready.")


def create_subnets(name_prefix, subnets):
    subnets_share = {"ids": [], "masks": {}}
    for snet in subnets:
        subnet_name = OCTAVIA_MGMT_SUBNET_PREFIX + snet["range"].translate(
            {ord(s): None for s in "./"}
        )
        subnet = ensure_openstack_resource(
            ost.network.find_subnet,
            ost.network.create_subnet,
            {
                "name": subnet_name,
                "network_id": network.id,
                "ip_version": "4",
                "cidr": snet["range"],
                "allocation_pools": [
                    {"start": snet["pool_start"], "end": snet["pool_end"]}
                ],
            },
        )
        subnets_share["ids"].append({"subnet_id": subnet.id})
        subnets_share["masks"].update({subnet.id: snet["range"].split("/")[1]})

    return subnets_share


def create_secgroups(names, remote_ports, host_port):
    ids = {
        name: ensure_openstack_resource(
            ost.network.find_security_group,
            ost.network.create_security_group,
            {"name": name},
        ).id
        for name in names
    }
    for dst_port in (22, OCTAVIA_OSH_LB_HM_REMOTE_PORT):
        create_security_group_rule(
            security_group_id=ids[OCTAVIA_SECGROUP_MGMT],
            direction="ingress",
            remote_ip_prefix="0.0.0.0/0",
            protocol="tcp",
            port_range_max=dst_port,
            port_range_min=dst_port,
        )
    create_security_group_rule(
        security_group_id=ids[OCTAVIA_SECGROUP_MGMT],
        direction="ingress",
        remote_ip_prefix="0.0.0.0/0",
        protocol="icmp",
    )
    create_security_group_rule(
        security_group_id=ids[OCTAVIA_SECGROUP_HEALTH_MANAGER],
        direction="ingress",
        remote_ip_prefix="0.0.0.0/0",
        protocol="udp",
        port_range_max=OCTAVIA_OSH_LB_HM_HOST_PORT,
        port_range_min=OCTAVIA_OSH_LB_HM_HOST_PORT,
    )
    return ids


def create_ports(port_prefix, network, subnets, secgroups):
    ports = {"ips": [], "config": [f"NETWORK_MTU={network.mtu}"]}
    octavia_hosts = [
        node.name
        for node in pykube.Node.objects(kube).filter(
            selector=dict([OCTAVIA_NODE_SELECTOR.split("=")])
        )
    ]
    for host in octavia_hosts:
        _host = host.replace("-", "_")
        port = ensure_openstack_resource(
            ost.network.find_port,
            ost.network.create_port,
            {
                "name": port_prefix + host,
                "network_id": network.id,
                "security_groups": secgroups,
                "device_owner": "Octavia:health-mgr",
                "fixed_ips": subnets["ids"],
                "binding:host_id": host,
            },
        )
        ports["ips"].append(
            f"{port.fixed_ips[0]['ip_address']}:{OCTAVIA_OSH_LB_HM_HOST_PORT}"
        )
        port_addrs = " ".join(
            [
                f"{p['ip_address']}/{subnets['masks'][p['subnet_id']]}"
                for p in port.fixed_ips
            ]
        )
        ports["config"].append(f"PORT_MAC_{_host}={port.mac_address}")
        ports["config"].append(f"PORT_ID_{_host}={port.id}")
        ports["config"].append(f"PORT_ADDRS_{_host}='{port_addrs}'")

    return ports


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def get_kube(klass, name, namespace):
    return klass.objects(kube).filter(namespace=namespace).get_or_none(name=name)


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def ensure_kube_resource(klass, data, name, namespace):
    ensure = "update" if get_kube(klass, name, namespace) else "create"
    getattr(klass(kube, data), ensure)()


# ENTRYPOINT
kube = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)
OS_CLOUD = os.getenv("OS_CLOUD", "envvars")
ost = openstack.connect(cloud=OS_CLOUD)
ost_system = ost

ost_system = openstack.connect(cloud=os.getenv("OS_CLOUD_SYSTEM", "envvars"))

if OCTAVIA_WAIT_NEUTRON_RESOURCES:
    # NOTE(vsaienko): wait for Neutron resources that involved in port
    # binding: dhcp agents and ovs-agents
    wait_neutron_resources(namespace=OCTAVIA_NAMESPACE)
    # Give some time for dhcp agents to process network/subnet
    time.sleep(60)

network = ensure_openstack_resource(
    ost.network.find_network, ost.network.create_network, {"name": OCTAVIA_MGMT_NET}
)
subnets = create_subnets(OCTAVIA_MGMT_SUBNET_PREFIX, json.loads(OCTAVIA_OSH_LB_SUBNETS))
secgroup_ids = create_secgroups(
    (OCTAVIA_SECGROUP_MGMT, OCTAVIA_SECGROUP_HEALTH_MANAGER),
    (22, OCTAVIA_OSH_LB_HM_REMOTE_PORT),
    OCTAVIA_OSH_LB_HM_HOST_PORT,
)

if OCTAVIA_MGMT_CREATE_PORTS:
    ports = create_ports(
        OCTAVIA_PORT_PREFIX,
        network,
        subnets,
        [secgroup_ids[OCTAVIA_SECGROUP_HEALTH_MANAGER]],
    )

flavor = ensure_openstack_resource(
    ost.compute.find_flavor,
    ost.compute.create_flavor,
    {
        "name": OCTAVIA_FLAVOR,
        "ram": 1024,
        "disk": 2,
        "vcpus": 1,
        "is_public": False,
    },
)
with open("/tmp/.ssh/octavia_ssh_key.pub", "r") as public_key:
    ensure_openstack_resource(
        ost.compute.find_keypair,
        ost.compute.create_keypair,
        {"name": "octavia_ssh_key", "public_key": public_key.read()},
    )
set_quotas(
    {
        "network": {"port": -1, "security_group": -1, "security_group_rule": -1},
        "compute": {
            "cores": -1,
            "instances": -1,
            "key_pairs": -1,
            "ram": -1,
        },
    }
)

LOG.info("Applying configmap %s ...", OCTAVIA_SETTINGS_CONFIGMAP)
settings = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": OCTAVIA_SETTINGS_CONFIGMAP,
        "namespace": OCTAVIA_NAMESPACE,
        "ownerReferences": [
            {
                "apiVersion": "v1",
                "name": "octavia-bin",
                "kind": "ConfigMap",
                "controller": True,
                "uid": get_kube(pykube.ConfigMap, "octavia-bin", OCTAVIA_NAMESPACE).obj[
                    "metadata"
                ]["uid"],
            }
        ],
    },
    "data": {
        "settings.conf": "\n".join(
            [
                "[controller_worker]",
                f"amp_secgroup_list={secgroup_ids[OCTAVIA_SECGROUP_MGMT]}",
                f"amp_flavor_id={flavor.id}",
                f"amp_boot_network_list={network.id}",
            ]
        )
    }
}
if OCTAVIA_MGMT_CREATE_PORTS:
    settings["data"]["settings.conf"] += '\n'.join(
        [
            "\n[health_manager]",
            f"bind_port={OCTAVIA_OSH_LB_HM_HOST_PORT}",
            f"controller_ip_port_list={','.join(ports['ips'])}",
        ]
    )
    settings["data"]["ports_configs"] = "\n".join(ports["config"])

ensure_kube_resource(
    pykube.ConfigMap, settings, OCTAVIA_SETTINGS_CONFIGMAP, OCTAVIA_NAMESPACE
)
LOG.info("  Done")
