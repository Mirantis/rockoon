#!/usr/bin/env python3
import asyncio
import argparse
import traceback
import ipaddress
import json
import logging
import os
import re
import sys
import time
import yaml


from abc import ABC, abstractmethod
from enum import Enum, auto

from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from jinja2 import Environment, BaseLoader
from pykube import ConfigMap

from rockoon import health
from rockoon import helm
from rockoon import kube
from rockoon import utils
from rockoon import osdplstatus
from rockoon import resource_view
from rockoon import services
from rockoon import settings
from rockoon.openstack_utils import OpenStackClientManager
from rockoon.layers import render_artifacts

MIGRATION_FINALIZER = "lcm.mirantis.com/ovs-ovn-migration.finalizer"
MIGRATION_STATE_CONFIGMAP_NAME = "ovs-ovn-migration-state"
BACKUP_NEUTRON_DB_PATH = "/var/lib/mysql"
MARIADB_FULL_BACKUP_TIMEOUT = 1200
MARIADB_NEUTRON_BACKUP_TIMEOUT = 600

TYPE_FLAT = "flat"
TYPE_VXLAN = "vxlan"
TYPE_VLAN = "vlan"
PROBLEMATIC_PROVIDER_TYPES = [TYPE_VLAN, TYPE_FLAT]
# sriov is supported only with flat and vlan networks
SRIOV_PROVIDER_TYPES = [TYPE_VLAN, TYPE_FLAT]
SRIOV_VNIC_TYPES = ["direct", "macvtap", "direct-physical", "virtio-forwarder"]
DEFAULT_GENEVE_HEADER_SIZE = 38
IP_HEADER_LENGTH = {
    4: 20,
    6: 40,
}

# Stage statuses
STARTED, COMPLETED, FAILED = ("started", "completed", "failed")

CLEANUP_NETNS_DS_TEMPLATE = """
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ovs-ovn-migration-cleanup
  namespace: openstack
  labels:
    app: ovs-ovn-migration-cleanup
spec:
  selector:
    matchLabels:
      app: ovs-ovn-migration
  template:
    metadata:
      labels:
        app: ovs-ovn-migration
    spec:
      hostNetwork: true
      nodeSelector:
        openvswitch: enabled
      initContainers:
      - name: cleanup
        image: {{image}}
        securityContext:
          privileged: true
          readOnlyRootFilesystem: true
          runAsNonRoot: false
          runAsUser: 0
        command:
          - /bin/bash
          - -c
          - |
            set -ex
            trap err_trap EXIT
            function err_trap {
                local r=$?
                if [[ $r -ne 0 ]]; then
                    echo "cleanup_netns FAILED"
                fi
                exit $r
            }
            OVS_DB_SOCK="--db=tcp:127.0.0.1:6640"
            EXIT_CODE=0
            for ns in $(egrep 'qrouter-|qdhcp-|snat-|fip-' <(cut -d' ' -f1 <(ip netns))); do
                for link in $(cut -d: -f2 <(grep -v LOOPBACK <(ip netns exec $ns ip -o link show))); do
                    link=${link%%@*}
                    ip netns exec $ns ip l delete $link || ovs-vsctl ${OVS_DB_SOCK} --if-exists del-port br-int $link
                done
                if [[ -n $(grep -v LOOPBACK <(ip netns exec $ns ip -o link show)) ]]; then
                    echo "Failed to clean all interfaces in network namespace $ns, namespace will not be removed"
                    EXIT_CODE=1
                else
                    echo "Cleaned all interfaces in network namespace $ns, removing namespace"
                    ip netns delete $ns
                fi
            done
            ovs-vsctl ${OVS_DB_SOCK} del-manager
            exit "${EXIT_CODE}"
        volumeMounts:
        - mountPath: /tmp
          name: pod-tmp
        - name: run-netns
          mountPath: /run/netns
          mountPropagation: Bidirectional
        - name: run-ovs
          mountPath: /run/openvswitch
      containers:
        - name: sleep
          image: {{image}}
          command:
           - sleep
           - infinity
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            capabilities:
              drop:
                - ALL
      volumes:
      - name: pod-tmp
        emptyDir: {}
      - name: run-netns
        hostPath:
          path: /run/netns
      - name: run-ovs
        hostPath:
          path: /run/openvswitch
      restartPolicy: Always
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
"""


def set_args():
    parser = argparse.ArgumentParser(
        prog="osctl-ovs-ovn-migrate",
        description="Migrate from OVS neutron backend to OVN.",
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="/tmp/ovs-ovn-migration",
        dest="log_dir",
        help=("Directory to store logs."),
    )
    subparsers = parser.add_subparsers(
        help="Parse subcommands of migration script", dest="mode"
    )
    subparsers.add_parser(
        "backup_db", help="Backup Neutron database before migration"
    )
    migrate_subparcer = subparsers.add_parser(
        "migration",
        help="Start migration process",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers.add_parser(
        "preflight_checks", help="OpenStack checks before migration"
    )
    migrate_subparcer.add_argument(
        "--non-interactive",
        action="store_false",
        dest="interactive",
        help=("Run migration in non interactive mode"),
    )
    migrate_subparcer.add_argument(
        "--max-workers",
        type=int,
        default=0,
        dest="max_workers",
        help=(
            """Maximum number of workers to spawn for parallel operations.
            If set to 0, internal defaults for operations will be used.
            For example for pods parallel operations (like exec) number of workers will be
            equal to number of target pods.
            """
        ),
    )

    args = parser.parse_args()
    if not args.mode:
        parser.error("Run mode does not specified")
    return args


def get_logger():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    logging_conf = yaml.safe_load(
        f"""
    disable_existing_loggers: false
    formatters:
      standard:
        format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    handlers:
      default:
        class: logging.StreamHandler
        formatter: standard
        stream: ext://sys.stdout
        level: INFO
      default_file:
        class: logging.FileHandler
        formatter: standard
        filename: {LOG_DIR}/ovs-ovn-migration.log
        level: DEBUG
    loggers:
      aiohttp:
        level: WARNING
      kopf:
        level: INFO
      kopf.activities.probe:
        level: WARNING
      opensearch:
        level: WARNING
      rockoon:
        level: INFO
      rockoon.cli.ovs_ovn_migration:
        level: DEBUG
    root:
      handlers:
      - default
      - default_file
      level: INFO
    version: 1
    """
    )
    logging.config.dictConfig(logging_conf)
    return logging.getLogger(__name__)


def check_input(check, msg, error_string="Illegal Input"):
    while True:
        result = input(f"[USER INPUT NEEDED] {msg} --> ").strip()
        if check(result):
            return result
        LOG.error(error_string)


class CheckStatus(Enum):
    SUCCESS = auto()
    WARNING = auto()
    ERROR = auto()

    def __str__(self):
        return self.name


class CheckImpact(Enum):
    MAJOR = auto()
    CRITICAL = auto()


class CheckBase(ABC):

    name = None
    error_message = None
    success_message = "No issues found"
    impact = CheckImpact.MAJOR
    violations = ["Check was not executed yet"]
    registry = {}

    def __init__(self, connect):
        self.oc = connect

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.id = cls.name.replace(" ", "_").lower()
        cls.registry[cls.id] = cls

    @abstractmethod
    def check(self):
        pass

    @property
    def status(self):
        if not self.violations:
            return CheckStatus.SUCCESS
        elif self.impact == CheckImpact.MAJOR:
            return CheckStatus.WARNING
        elif self.impact == CheckImpact.CRITICAL:
            return CheckStatus.ERROR

    @property
    def description(self):
        if self.is_success:
            return self.success_message
        return self.error_message

    @property
    def is_success(self):
        return self.status == CheckStatus.SUCCESS

    @property
    def report(self):
        return {
            self.id: {
                "state": str(self.status),
                "description": self.description,
                "violations": self.violations,
            }
        }

    def log(self):
        log_method = LOG.debug
        log_base = f"{self.name} succeeded:\n"
        if not self.is_success:
            log_base = f"{self.name} is FAILED:\n"
            if self.status == CheckStatus.WARNING:
                log_method = LOG.warning
            elif self.status == CheckStatus.ERROR:
                log_method = LOG.error

        log_record = self.report[self.id]
        log_record["violations"] = len(log_record["violations"])
        log_record = log_base + yaml.dump(log_record)
        log_method(log_record)

    def run_check(self):
        try:
            self.violations = self.check()
        except Exception as e:
            LOG.exception(e)
            self.violations = [f"Exception {type(e).__name__}"]
            self.error_message = f"Check function '{self.check.__name__}' throws an exception '{type(e).__name__}: {e}'."
        self.log()
        return self.report

    def _get_security_group_dhcp_allowed_ipv4(self):
        """Return dictionary. The dictionary key corresponds to security group Id and
        value is a list of IPv4 CIDRs from this security group where access to DHCP is
        enabled. IPs are stored in IPv4Network format.
        """
        dhcp_allowed_sg = {}
        wildcard_cidr = ipaddress.ip_network("0.0.0.0/0")
        for sec_group in self.oc.network.security_groups():
            networks = []
            for rule in sec_group.security_group_rules:
                # Process egress rules for IPv4
                if (
                    rule["direction"] == "egress"
                    and rule["ethertype"] == "IPv4"
                ):
                    # The DHCP port has no security group
                    if not rule["remote_group_id"] is None:
                        continue
                    # Rule must be protocol independent
                    # or allow access to 67 port by UDP
                    if rule["protocol"] is None or (
                        rule["protocol"].lower() in ["udp", "17"]
                        and (
                            rule["port_range_min"] is None
                            or rule["port_range_min"] <= 67
                        )
                        and (
                            rule["port_range_max"] is None
                            or rule["port_range_max"] >= 67
                        )
                    ):
                        if rule["remote_address_group_id"] is None:
                            # Get CIDR from rule definition
                            if rule["normalized_cidr"] is None:
                                networks.append(wildcard_cidr)
                            else:
                                networks.append(
                                    ipaddress.ip_network(
                                        rule["normalized_cidr"]
                                    )
                                )
                        else:
                            # Get CIDRs if they are stored in address group
                            for cidr in self.oc.network.get_address_group(
                                rule["remote_address_group_id"]
                            ).addresses:
                                net = ipaddress.ip_network(cidr)
                                if net.version == 4:
                                    networks.append(net)
            if networks:
                dhcp_allowed_sg.update({sec_group.id: networks})
        return dhcp_allowed_sg

    def _are_addresses_allowed_by_firewall(
        self, tested_cidrs, permitted_cidrs
    ):
        """param: tested_cidrs - list of IPv4Network
        param: permitted_cidrs - list of IPv4Network
        return: True if all subnets from tested_cidrs are in
                networks from permitted_cidrs
        """
        if ipaddress.ip_network("0.0.0.0/0") in permitted_cidrs:
            return True
        for subnet in tested_cidrs:
            is_blocked = True
            for net in permitted_cidrs:
                if net.prefixlen <= subnet.prefixlen:
                    if subnet in net.subnets(new_prefix=subnet.prefixlen):
                        is_blocked = False
                        break
            if is_blocked:
                return False
        return True

    def _get_port_cidrs_with_dhcp4(self, port):
        """
        param: port - openstack.network.v2.port.Port object
        return: list CIDRs of IPv4 subnets where dhcp is enabled
                CIDRs are stored in IPv4Network format.
        """
        result = []
        subnet_ids = set()
        for fip in port.fixed_ips:
            subnet_ids.add(fip["subnet_id"])
        for id in subnet_ids:
            subnet = self.oc.network.get_subnet(id)
            if subnet.is_dhcp_enabled and subnet.ip_version == 4:
                result.append(ipaddress.ip_network(subnet.cidr))
        return result

    def _subnet_has_workload_ports(self, subnet_id):
        ports = self.oc.network.get_subnet_ports(subnet_id)
        for port in ports:
            if not (
                port.device_owner.startswith("network")
                or port.device_owner.startswith("neutron")
            ):
                return True
        return False

    def _router_network_mtu_map(self, router, network_type=None):
        ports = self.oc.list_router_interfaces(router, network_type)
        networks = {}
        for p in ports:
            network = self.oc.get_network(p.network_id)
            # network can be removed after we get router interfaces
            if network:
                networks[p.network_id] = network.mtu
            else:
                LOG.debug(
                    f"Not found network {p.network_id}, skipping port {p.id}"
                )
        return networks

    def _get_network_connected_routers(self, net_id):
        routers = []
        for device_owner in [
            "network:ha_router_replicated_interface",
            "network:router_interface_distributed",
            "network:router_interface",
            "network:router_gateway",
        ]:
            for port in self.oc.network.ports(
                network_id=net_id, device_owner=device_owner
            ):
                routers.append(port.device_id)
        return routers

    def _get_port_floating_ips(self, port_id):
        return [
            fip.floating_ip_address
            for fip in self.oc.network.ips(port_id=port_id)
        ]


class SubnetsIpAvailabilityCheck(CheckBase):

    name = "Subnets IP address availability check"
    impact = CheckImpact.MAJOR
    error_message = (
        "Found subnets that do not have free IPs. "
        "Metadata ports may not be created aftser migration. "
        "Metadata will not be available for instances after migration. "
    )

    def check(self):
        LOG.info("Process subnets for free IPs.")
        overfilled_subnets = []
        for net in self.oc.network.networks():
            LOG.debug(f"Checking free ips in subnet of network {net.name}.")
            for subnet in self.oc.network.get_network_ip_availability(
                net.id
            ).subnet_ip_availability:
                if subnet.get("used_ips") == subnet.get("total_ips"):
                    overfilled_subnets.append(subnet.get("subnet_id"))
        LOG.info("Finished processing subnets for free IPs.")
        return overfilled_subnets


class NetworksMtuCheck(CheckBase):

    name = "Networks MTU size check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found networks that have unsuitable MTU size for Geneve. "
        "Workloads availability will be broken after migration. "
        "Please adjust MTU for networks. "
        "Migration is not recommended."
    )

    def check(self):
        osdpl = kube.get_osdpl()
        network_params = (
            osdpl.obj.get("spec", {})
            .get("services", {})
            .get("networking", {})
            .get("neutron", {})
            .get("values", {})
            .get("conf", {})
            .get("neutron", {})
        )
        mtu = []
        mtu.append(
            network_params.get("DEFAULT", {}).get("global_physnet_mtu", 1500)
        )
        path_mtu = network_params.get("ml2", {}).get("path_mtu", 0)
        if path_mtu > 0:
            mtu.append(path_mtu)

        ip_version = network_params.get("ml2", {}).get("overlay_ip_version", 4)
        max_mtu_for_network = (
            min(mtu)
            - IP_HEADER_LENGTH[ip_version]
            - DEFAULT_GENEVE_HEADER_SIZE
        )
        bad_mtu_networks = []
        LOG.info("Check MTU value for networks.")
        for net in self.oc.network.networks(provider_network_type=TYPE_VXLAN):
            if net.mtu > max_mtu_for_network:
                bad_mtu_networks.append(net.id)
        LOG.info("Finished check MTU value for networks.")
        return bad_mtu_networks


class NetworksProviderTypeCheck(CheckBase):

    name = "Networks provider type check"
    impact = CheckImpact.MAJOR
    error_message = (
        "Found networks (containing instances) which have problematic provider network type. "
        f"OVN has multiple issues related to usage of {PROBLEMATIC_PROVIDER_TYPES} networks."
    )

    def check(self):
        nets = {}
        LOG.info("Checking networks provider type")
        for net_type in PROBLEMATIC_PROVIDER_TYPES:
            for net in self.oc.network.networks(
                provider_network_type=net_type
            ):
                if not self._get_network_connected_routers(net.id):
                    for port in self.oc.network.ports(
                        network_id=net.id, device_owner="compute:nova"
                    ):
                        nets.setdefault(net.id, {"instances": []})
                        nets[net.id]["instances"].append(port.device_id)
                        nets[net.id]["provider_type"] = net_type
        LOG.info("Finished checking networks provider type")
        return nets


class NetworksProviderTypeRoutingCheck(CheckBase):

    name = "Networks provider type routing check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found networks (containing instances) which have problematic provider network type and "
        f"are connected to routers. OVN has issues with routing of {PROBLEMATIC_PROVIDER_TYPES} "
        "networks. Each use case should be carefully checked. Migration "
        "is not recommended."
    )

    def check(self):
        routed_nets = {}
        LOG.info("Checking networks provider type and routing")
        for net_type in PROBLEMATIC_PROVIDER_TYPES:
            for net in self.oc.network.networks(
                provider_network_type=net_type
            ):
                routers = self._get_network_connected_routers(net.id)
                if routers:
                    instances = []
                    for port in self.oc.network.ports(
                        network_id=net.id, device_owner="compute:nova"
                    ):
                        instances.append(port.device_id)
                    if instances:
                        routed_nets.update(
                            {
                                net.id: {
                                    "routers": routers,
                                    "instances": instances,
                                    "provider_type": net_type,
                                }
                            }
                        )
        LOG.info("Finished checking networks provider type and routing")
        return routed_nets


class TenantNetworkTypesCheck(CheckBase):

    name = "Neutron tenant network types check"
    impact = CheckImpact.MAJOR
    error_message = (
        "Found tenant_network_types option containing VXLAN network type. "
        "Recommended network type for OVN is Geneve. "
        "When migrating to OVN all existing VXLAN networks will be converted "
        "to Geneve regardless of this setting. In case VXLAN was the default "
        "tenant network type it will be replaced by Geneve."
    )

    def check(self):
        LOG.info("Checking Neutron tenant_network_types")
        osdpl = kube.get_osdpl()
        mspec = osdpl.mspec
        result = []
        features_path = ["features", "neutron", "tenant_network_types"]
        features_tnt = utils.get_in(mspec, features_path, [])
        if "vxlan" in features_tnt:
            result.append(":".join(features_path))

        base_path = ["services", "networking", "neutron", "values", "conf"]
        neutron_conf = utils.get_in(mspec, base_path, {})
        tnt_paths = utils.find_key_paths(neutron_conf, "tenant_network_types")
        for path in tnt_paths:
            if "ml2" == path[-1]:
                tnt_path = list(path) + ["tenant_network_types"]
                services_tnt = utils.get_in(neutron_conf, tnt_path, "")
                if "vxlan" in services_tnt:
                    result.append(":".join(base_path + tnt_path))
        LOG.info("Finished checking Neutron tenant_network_types")
        return result


class SubnetsNoDHCPCheck(CheckBase):
    name = "Subnets without enabled DHCP check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found subnets that do not have DHCP. "
        "Correct MTU settings will not be propagated automatically. "
        "Please configure the MTU of instances in these subnets manually. "
        "Migration is not recommended."
    )

    def check(self):
        no_dhcp_subnets = []
        LOG.info("Check if DHCP is enabled in subnets.")
        for net in self.oc.network.networks(provider_network_type=TYPE_VXLAN):
            for subnet_id in net.subnet_ids:
                if not self.oc.network.get_subnet(
                    subnet_id
                ).is_dhcp_enabled and self._subnet_has_workload_ports(
                    subnet_id
                ):
                    no_dhcp_subnets.append(subnet_id)
        LOG.info("Finished check for DHCP enabling.")
        return no_dhcp_subnets


class SubnetsDNSServersCheck(CheckBase):

    name = "Subnets without dns_nameservers check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found subnets that do not have dns nameservers set. "
        "Access to DNS from instances will be broken. "
        "Please set dns nameservers for subnets manually. "
        "Migration is not recommended."
    )

    def check(self):
        """
        Checks whether dhcp enabled subnets have dns_nameservers set. Check
        is failed if list of dns servers is empty.
        """
        no_dns_subnets = []
        LOG.info("Checking subnets have dns_nameservers set")
        for subnet in self.oc.network.subnets(is_dhcp_enabled=True):
            if not subnet.dns_nameservers and self._subnet_has_workload_ports(
                subnet.id
            ):
                no_dns_subnets.append(subnet.id)
        LOG.info("Finished checking subnets have dns_nameservers set")
        return no_dns_subnets


class PortsSRIOVFloatingIPsCheck(CheckBase):

    name = "SRIOV ports floating ip check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found SRIOV ports attached to instances with floating ip addresses."
        "OVN has issues with connectivity to SRIOV ports through floating ip "
        "addresses. Migration is not recommended."
    )

    def check(self):
        sriov_with_fips = {}
        LOG.info("Checking sriov ports and floating ips")
        for net_type in SRIOV_PROVIDER_TYPES:
            for net in self.oc.network.networks(
                provider_network_type=net_type
            ):
                for port in self.oc.network.ports(
                    network_id=net.id, device_owner="compute:nova"
                ):
                    if port.binding_vnic_type in SRIOV_VNIC_TYPES:
                        # one port can have several fixed ips each with own floating ip
                        floating_ips = self._get_port_floating_ips(port.id)
                        if floating_ips:
                            sriov_with_fips.update({port.id: floating_ips})
        LOG.info("Finished checking sriov ports and floating ips")
        return sriov_with_fips


class PortsDHCPAccessCheck(CheckBase):

    name = "Ports with blocked access to DHCPv4 check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found ports which have incorrect security group rules for access to DHCP. "
        "Instances may lose network connectivity after migration. "
        "Please configure correct rules to allow access to DHCPv4 service. "
        "Migration is not recommended."
    )

    def check(self):
        """Test VM ports from networks which are not connected to external routers.
        The test is considered successful if all subnets of the port with enable_dhcp==True
        param have access to 67 UDP port and allow packets to the 255.255.255.255 address.
        """
        allowed_sg = self._get_security_group_dhcp_allowed_ipv4()
        broadcast_ip = ipaddress.ip_network("255.255.255.255/32")
        ports_blocked = []
        LOG.info("Check if DHCP is allowed by security groups on the ports.")
        for net in self.oc.network.networks(is_router_external=False):
            for port in self.oc.network.ports(network_id=net.id):
                if port.is_port_security_enabled and port.device_owner in [
                    "compute:nova",
                    "",
                ]:
                    port_cidrs_with_dhcp = self._get_port_cidrs_with_dhcp4(
                        port
                    )
                    if len(port_cidrs_with_dhcp) == 0:
                        continue

                    permitted_cidrs = set()
                    for sg in port.security_group_ids:
                        if sg in allowed_sg.keys():
                            permitted_cidrs.update(allowed_sg[sg])

                    # If port has permissions to broadcast and 67 UDP port it will get IP via DHCP
                    is_access_allowed = (
                        self._are_addresses_allowed_by_firewall(
                            [broadcast_ip], permitted_cidrs
                        )
                        and self._are_addresses_allowed_by_firewall(
                            port_cidrs_with_dhcp, permitted_cidrs
                        )
                    )
                    if not is_access_allowed:
                        ports_blocked.append(port.id)
        LOG.info("Finished ports check for access to DHCP.")
        return ports_blocked


class RouterGatewayMtuCheck(CheckBase):

    name = "Routers gateway MTU check"
    impact = CheckImpact.MAJOR
    error_message = (
        "OVN can only send packet 'ICMP fragmentation needed'. "
        "It may not be handled by all workloads correctly. "
        "Additional analysis is needed."
    )

    def check(self):
        gw_mtu = {}
        LOG.info("Check gateway MTU value for routers.")
        for router in self.oc.network.routers():
            if router.external_gateway_info:
                networks = self._router_network_mtu_map(router)
                if len(set(networks.values())) > 1:
                    gw_mtu[router.id] = {
                        "networks_mtu": networks,
                        "external_net_id": router.external_gateway_info[
                            "network_id"
                        ],
                    }
        LOG.info("Finished check MTU value for routers.")
        return gw_mtu


class RouterInternalMtuCheck(CheckBase):

    name = "Routers internal MTU check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Since OVN can not fragment packets by itself "
        "connectivity between specified networks will be broken. "
        "Please make sure that all networks plugged into the router "
        "have the same MTU value. "
        "Migration is not recommended."
    )

    def check(self):
        internal_mtu = {}
        LOG.info("Check internal MTU value for routers.")
        for router in self.oc.network.routers():
            networks = self._router_network_mtu_map(router, "internal")
            if len(set(networks.values())) > 1:
                internal_mtu[router.id] = {"networks_mtu": networks}
        LOG.info("Finished check MTU value for routers.")
        return internal_mtu


class UnsupportedFeaturesCheck(CheckBase):

    name = "Unsupported features check"
    impact = CheckImpact.CRITICAL
    error_message = (
        "Found unsupported features enabled on environment. These "
        "features become unavailable after migration to OVN and can "
        "block migration itself. To proceed with migration they should "
        "be disabled by editing OsDpl object."
    )

    def check(self):
        LOG.info("Checking unsupported features")
        osdpl = kube.get_osdpl()
        mspec = osdpl.mspec
        result = {}
        bgpvpn = ["features", "neutron", "bgpvpn", "enabled"]
        bgpvpn_enabled = utils.get_in(mspec, bgpvpn, False)
        ipsec = ["features", "neutron", "ipsec", "enabled"]
        ipsec_enabled = utils.get_in(mspec, ipsec, False)
        if bgpvpn_enabled:
            result.update(
                {"bgpvpn": f"Please set {':'.join(bgpvpn)} to False"}
            )
        if ipsec_enabled:
            result.update({"ipsec": f"Please set {':'.join(ipsec)} to False"})
        LOG.info("Finished checking unsupported features")
        return result


class StateCM:

    labels = {"lcm.mirantis.com/ovs-ovn-migration": "state"}

    def __init__(self, name, namespace, stages):
        self.name = name
        self.namespace = namespace
        cm = [
            cm
            for cm in kube.resource_list(
                ConfigMap,
                self.labels,
                namespace=namespace,
            )
        ]
        if len(cm) > 1:
            raise ValueError("Found more than one existing state configmap")
        if not cm:
            LOG.info("State configmap does not exist, creating")
            self.cm = self.create(stages)
        else:
            LOG.warning("State configmap already exists")
            self.cm = cm[0]

    def create(self, stages):
        """Create configmap in format:
        <stage1_name>: '{"status": "init", "error": null}'
        <stage2_name>: '{"status": "init", "error": null}'
        and returns k8s configmap object
        """
        stage_init_state = {"status": "init", "error": None}
        state_cm = kube.dummy(
            ConfigMap,
            self.name,
            namespace=self.namespace,
        )
        state_cm.metadata["labels"] = self.labels
        state_cm.obj["data"] = {
            stage["name"]: json.dumps(stage_init_state) for stage in stages
        }
        state_cm.create()
        return state_cm

    @property
    def state(self):
        self.cm.reload()
        cm_data = self.cm.obj.get("data", {})
        data = {k: json.loads(v) for k, v in cm_data.items()}
        return data

    def update(self, stage, status, error=None):
        state = self.state
        state[stage] = {"status": status, "error": error}
        self.cm.obj["data"] = {k: json.dumps(v) for k, v in state.items()}
        self.cm.update(is_strategic=False)


def get_service(osdpl, service):
    osdpl.reload()
    mspec = osdpl.mspec
    child_view = resource_view.ChildObjectView(mspec)
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    svc = services.registry[service](mspec, LOG, osdplst, child_view)
    return svc


def get_objects_by_id(svc, id):
    # switch case is supported from python 3.10
    if id == "openvswitch-ovn-db":
        return [svc.get_child_object("StatefulSet", "openvswitch-ovn-db")]
    elif id == "openvswitch-ovn-northd":
        return [svc.get_child_object("StatefulSet", "openvswitch-ovn-northd")]
    elif id == "ovn-controller":
        return svc.get_child_objects_dynamic("DaemonSet", "ovn-controller")
    elif id == "openvswitch-vswitchd":
        return svc.get_child_objects_dynamic(
            "DaemonSet", "openvswitch-vswitchd"
        )
    elif id == "neutron-ovs-agent":
        return svc.get_child_objects_dynamic("DaemonSet", "neutron-ovs-agent")
    elif id == "neutron-l3-agent":
        return svc.get_child_objects_dynamic("DaemonSet", "neutron-l3-agent")
    elif id == "neutron-ovn-db-sync-migrate":
        return [svc.get_child_object("Job", "neutron-ovn-db-sync-migrate")]
    elif id == "neutron-metadata-agent":
        return svc.get_child_objects_dynamic(
            "DaemonSet", "neutron-metadata-agent"
        )
    elif id == "neutron-server":
        return svc.get_child_objects_dynamic("DaemonSet", "neutron-server")
    elif id == "mariadb-server":
        return [svc.get_child_object("StatefulSet", "mariadb-server")]
    elif id == "neutron-rabbitmq":
        return [
            svc.get_child_object(
                "StatefulSet", "openstack-neutron-rabbitmq-rabbitmq"
            )
        ]
    else:
        raise ValueError("Unknown object id {id}")


def update_service_release(hm, service, release_name, patch):
    """Updates only specified release for service with patched values"""
    bundle = service.render()
    for release in bundle["spec"]["releases"]:
        if release["name"] == release_name:
            utils.merger.merge(release["values"], patch)
            bundle["spec"]["releases"] = [release]
            break
    asyncio.run(hm.install_bundle(bundle))


def wait_for_objects_ready(service, object_ids, timeout=1200):
    """
    Waits for child objects of the service to be ready

    :param service: Object of type Service
    :param object_ids: List of strings
    :returns None
    """
    LOG.info(f"Waiting for {object_ids} to be ready")
    for id in object_ids:
        for obj in get_objects_by_id(service, id):
            asyncio.run(obj.wait_ready(timeout=timeout))
    LOG.info(f"{object_ids} are ready")


def wait_for_objects_absent(service, object_ids, timeout=600):
    """
    Waits for child objects of the service to be absent

    :param service: Object of type Service
    :param object_ids: List of strings
    :param timeout: integer
    :returns None
    """
    for id in object_ids:
        for obj in get_objects_by_id(service, id):
            wait_for_object_absent(obj, timeout)


def wait_for_object_absent(obj, timeout=600):
    """
    Waits for k8s object to be absent

    :param obj: pykube obj
    :param timeout: integer
    :returns None
    """
    LOG.info(f"Waiting {timeout} for {obj} to be absent")
    start_time = int(time.time())
    while True:
        if not obj.exists():
            break
        time.sleep(30)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            msg = f"Failed to wait for {obj} to be absent"
            LOG.error(msg)
            raise TimeoutError(msg)
    LOG.info(f"{obj} is absent")


def daemonsets_check_exec(results, raise_on_error=True):
    failed_nodes = []
    for res in results:
        LOG.debug(
            f"""
        DaemonSet {res['daemonset']} Pod {res['pod']}:{res['container']} exec results:
            NODE:
              {res['node']}
            COMMAND:
              {res['command']}
            STATUS:
              {res['status']}
            STDERR:
              {res['stderr']}
            STDOUT:
              {res['stdout']}
            ERROR:
              {res['error_json']}
            EXCEPTION:
              {res['exception']}
        """
        )
        if res["status"] != "Success":
            failed_nodes.append(res["node"])
    if failed_nodes:
        LOG.error(f"Failed to execute command on nodes {failed_nodes}")
        if raise_on_error:
            raise RuntimeError("Failed to run exec for daemonsets")


def daemonsets_exec_parallel(
    daemonsets,
    command,
    container,
    max_workers=0,
    timeout=30,
    raise_on_error=True,
    nodes=None,
):
    """Run exec inside pods of different daemonsets in parallel
    :param daemonsets: List of kube.DaemonSet objects
    :param command: List of strings
    :param container: String with name of container chosen for command execution
    :param max_workers: Integer number of max parallel threads to spawn
    :param timeout: timeout for command execution inside pod.
    :param nodes: List of nodes selected to run command. If set, command will
                  be run only in pods on specified nodes.
    :returns List of dictionnaries in format
    """
    pods_map = {}
    pods = []
    for ds in daemonsets:
        pods_map[ds] = ds.pods
        pods.extend(pods_map[ds])
    if not max_workers:
        max_workers = len(pods)
    if nodes:
        pods = [
            pod for pod in pods if pod.obj["spec"].get("nodeName") in nodes
        ]
    # Maximum time to wait for all workers to finish
    pool_timeout = len(pods) * timeout
    args = [command]
    kwargs = {
        "container": container,
        "raise_on_error": False,
        "timeout": timeout,
    }
    future_data = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        LOG.info(
            f"Running command {command} on pods of daemonsets {daemonsets}"
        )
        for pod in pods:
            future = executor.submit(pod.exec, *args, **kwargs)
            future_data[pod] = future
        LOG.info(f"Waiting command on pods of daemonsets {daemonsets}")
        done, not_done = wait(
            future_data.values(),
            return_when=ALL_COMPLETED,
            timeout=pool_timeout,
        )
        LOG.info(f"Done waiting command on pods of daemonsets {daemonsets}")
    results = []
    for pod, future in future_data.items():
        for ds in daemonsets:
            if pod in pods_map[ds]:
                pod_ds = ds
        data = {
            "daemonset": pod_ds.name,
            "node": pod.obj["spec"].get("nodeName"),
            "pod": pod.name,
            "container": container,
            "command": command,
            "error_json": {},
            "exception": None,
            "stderr": "",
            "stdout": "",
            "status": "Unknown",
        }
        if future in done:
            result = future.result()
            data["error_json"] = result["error_json"]
            data["exception"] = result["exception"]
            data["stderr"] = result["stderr"]
            data["stdout"] = result["stdout"]
            if result["timed_out"]:
                data["status"] = "Timed_out"
            elif result["exception"]:
                data["status"] = "Failure"
            elif "status" in data["error_json"]:
                data["status"] = data["error_json"]["status"]
        elif future in not_done:
            data["status"] = "Pool_timed_out"
        results.append(data)
    daemonsets_check_exec(results, raise_on_error)
    return results


def get_pod_logs(name, namespace, container, base_path, timestamps=False):
    """Get logs from pod and write them to file"""
    log_path = os.path.join(base_path, f"{container}.log")
    try:
        if not os.path.exists(base_path):
            os.makedirs(base_path)
        pod = kube.find(kube.Pod, name, namespace)
        with open(log_path, "w") as f:
            f.write(pod.logs(container=container, timestamps=timestamps))
        return True
    except Exception as e:
        LOG.exception(e)
        LOG.warning(f"Failed to get logs from pod {name}")
    return False


def get_daemonset_logs(
    ds, container, timestamps=False, max_workers=0, timeout=3600
):
    """Get logs from daemonset pods in parallel
    :param ds: kube.DaemonSet object
    :param container: name of container to gather logs from
    :param timestamps: Boolean whether to add timestamps to logs.
    :param max_workers: Integer number of max parallel threads to spawn
    :param timeout: timeout for logs gathering from all pods.
    :returns None
    """
    kwargs = {"timestamps": timestamps}
    if not max_workers:
        max_workers = os.cpu_count()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        LOG.info(f"Start gathering pods logs for daemonset {ds.name}")
        future_data = {}
        for pod in ds.pods:
            node = pod.obj["spec"].get("nodeName")
            args = [
                pod.name,
                pod.namespace,
                container,
                os.path.join(LOG_DIR, node, pod.name),
            ]
            future = executor.submit(get_pod_logs, *args, **kwargs)
            future_data[pod] = future
        done, not_done = wait(
            future_data.values(),
            return_when=ALL_COMPLETED,
            timeout=timeout,
        )
        LOG.info(f"Done gathering pods logs for daemonset {ds.name}")
    for pod, future in future_data.items():
        node = pod.obj["spec"].get("nodeName")
        if future in done:
            if not future.result():
                LOG.warning(f"Failed to get logs from node {node}")
        elif future in not_done:
            LOG.warning(f"Timed out getting logs from node {node}")


def cleanup_api_resources():
    """Cleanup resources from Openstack API related to neutron ovs backend"""
    ocm = OpenStackClientManager()
    LOG.info("Starting Neutron API resources cleanup")
    for device_owner in [
        "network:dhcp",
        "network:router_ha_interface",
        "network:floatingip_agent_gateway",
    ]:
        LOG.info(f"Cleaning Neutron {device_owner} ports")
        try:
            ocm.network_ensure_ports_absent(device_owner)
        except Exception:
            LOG.exception(f"Failed to clean some {device_owner} ports")
        LOG.info(f"Finished cleaning Neutron {device_owner} ports")
    for agent_type in [
        "Open vSwitch agent",
        "DHCP agent",
        "L3 agent",
        "Metadata agent",
    ]:
        LOG.info(f"Cleaning Neutron {agent_type} agents")
        for agent in ocm.network_get_agents(agent_type=agent_type):
            try:
                ocm.oc.network.delete_agent(agent)
            except Exception:
                LOG.exception(f"Failed to clean agent {agent}")
        LOG.info(f"Finished cleaning Neutron {agent_type} agents")
    for net in ocm.oc.network.networks():
        if re.match(r"^HA network tenant\s", net.name):
            LOG.info(f"Cleaning Neutron HA tenant network {net.name}")
            try:
                ocm.oc.network.delete_network(net)
            except Exception:
                LOG.exception(f"Failed to clean network {net.name}")
            LOG.info(f"Finished cleaning Neutron HA tenant network {net.name}")
    LOG.info("Finished Neutron API resources cleanup")


def cleanup_linux_netns(script_args):
    """Cleanup linux network namespaces and
    related network interfaces
    """
    osdpl = kube.get_osdpl()
    cleanup_image = render_artifacts(osdpl.mspec)["openvswitch_vswitchd"]
    rtemplate = Environment(loader=BaseLoader()).from_string(
        CLEANUP_NETNS_DS_TEMPLATE
    )
    data = rtemplate.render(image=cleanup_image)
    cleanup_ds = kube.resource(yaml.safe_load(data))
    if cleanup_ds and cleanup_ds.exists():
        cleanup_ds.delete(propagation_policy="Foreground")
        wait_for_object_absent(cleanup_ds)
    LOG.info("Cleaning network namespaces")
    try:
        LOG.info("Creating cleaning daemonset")
        cleanup_ds.create()
        asyncio.run(cleanup_ds.wait_ready(timeout=3600))
    finally:
        LOG.info("Gathering cleanup network namespaces logs")
        get_daemonset_logs(
            cleanup_ds,
            "cleanup",
            timestamps=True,
            max_workers=script_args.max_workers,
        )
        for pod in cleanup_ds.pods:
            node = pod.obj["spec"].get("nodeName")
            if not pod.ready:
                LOG.error(
                    f"Node {node} cleanup timeout"
                    f"Check logs in {os.path.join(LOG_DIR, node, pod.name)}"
                )
        LOG.info("Removing cleaning daemonset")
        cleanup_ds.delete(propagation_policy="Foreground")
        wait_for_object_absent(cleanup_ds)
    LOG.info("Finished cleaning network namespaces")


def prepare(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info("Backing up OVS bridge mappings")
    backup_bridge_mappings = """
    set -ex
    trap err_trap EXIT
    function err_trap {
        local r=$?
        if [[ $r -ne 0 ]]; then
            echo "prepare FAILED"
        fi
        exit $r
    }
    echo "Getting original bridge mapping"
    bm=$(cut -d= -f2 <(grep bridge_mappings /etc/neutron/plugins/ml2/openvswitch_agent.ini))
    [[ -z $bm ]] && echo bridge_mappings is empty! && exit 1
    echo "Original bridge mapping is ${bm}"
    ovs-vsctl set Open_Vswitch . external-ids:ovn-bridge-mappings-back="${bm// /}"
    echo "Finished original bridge mapping backup"
    """
    neutron_ovs_agents = get_objects_by_id(network_svc, "neutron-ovs-agent")
    daemonsets_exec_parallel(
        neutron_ovs_agents,
        ["bash", "-c", backup_bridge_mappings],
        "neutron-ovs-agent",
        max_workers=script_args.max_workers,
    )


def deploy_ovn_db(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info(
        "Modifying openvswitch and neutron-l3-agent finalizers to prevent early deletion"
    )
    for daemonset in ["openvswitch-vswitchd", "neutron-l3-agent"]:
        for ds in get_objects_by_id(network_svc, daemonset):
            LOG.info(
                f"Adding finalizer {MIGRATION_FINALIZER} to DaemonSet {ds}"
            )
            ds.ensure_finalizer_present(MIGRATION_FINALIZER)

    LOG.info("Patching Openstack deployment to deploy ovn database")
    osdpl.patch(
        {
            "spec": {
                "migration": {
                    "neutron": {"ovs_ovn_migration": True},
                },
                "features": {"neutron": {"backend": "ml2/ovn"}},
                "services": {
                    "compute": {
                        "nova": {
                            "values": {
                                "pod": {
                                    "lifecycle": {
                                        "upgrades": {
                                            "daemonsets": {
                                                "pod_replacement_strategy": "OnDelete"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "libvirt": {
                            "values": {
                                "pod": {
                                    "lifecycle": {
                                        "upgrades": {
                                            "daemonsets": {
                                                "pod_replacement_strategy": "OnDelete"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                    "networking": {
                        "neutron": {
                            "values": {
                                "manifests": {
                                    "deployment_server": False,
                                    "daemonset_metadata_agent": False,
                                }
                            }
                        },
                        "openvswitch": {
                            "values": {
                                "manifests": {
                                    "daemonset_ovn_controller": False
                                }
                            }
                        },
                    },
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    network_svc = get_service(osdpl, "networking")
    wait_for_objects_ready(
        network_svc,
        ["openvswitch-ovn-db", "openvswitch-ovn-northd"],
    )
    LOG.info("Deployment OVN db done")


def deploy_ovn_controllers(script_args):
    """Deploys ovn controllers in migration mode and syncs ovn db"""
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    helm_manager = helm.HelmManager(namespace=osdpl.namespace)
    osdpl.patch({"spec": {"draft": True}})

    LOG.info("Disable Neutron rabbimq")
    disable_rabbitmq_patch = {"manifests": {"statefulset": False}}
    update_service_release(
        helm_manager,
        network_svc,
        "openstack-neutron-rabbitmq",
        disable_rabbitmq_patch,
    )
    wait_for_objects_absent(network_svc, ["neutron-rabbitmq"])
    LOG.info("Neutron rabbimq is disabled")

    if not ovn_daemonsets:
        LOG.info("Deploying ovn controllers in migration mode")
        ovs_patch = {
            "conf": {
                "ovn_migration": True,
            },
            "manifests": {"daemonset_ovn_controller": True},
        }
        update_service_release(
            helm_manager,
            network_svc,
            "openstack-openvswitch",
            ovs_patch,
        )
        # ovn controllers should be already running and ready before we running ovn db sync
        wait_for_objects_ready(
            network_svc,
            ["openvswitch-ovn-db", "openvswitch-ovn-northd", "ovn-controller"],
        )
    LOG.info("Starting Neutron database sync to OVN database")
    neutron_patch = {"manifests": {"job_ovn_db_sync_migrate": True}}
    update_service_release(
        helm_manager, network_svc, "openstack-neutron", neutron_patch
    )
    # On large environments ovn db sync can take a lot of time
    wait_for_objects_ready(
        network_svc, ["neutron-ovn-db-sync-migrate"], timeout=3600
    )
    LOG.info("Neutron database sync to OVN database is completed")
    # Enable server without messaging dependency
    LOG.info("Starting neutron server to process OVN ports")
    utils.merger.merge(
        neutron_patch,
        {
            "manifests": {
                "deployment_server": True,
            },
            "dependencies": {
                "static": {
                    "server": {
                        "services": [
                            {"endpoint": "internal", "service": "oslo_db"},
                            {"endpoint": "internal", "service": "oslo_cache"},
                            {"endpoint": "internal", "service": "identity"},
                        ]
                    }
                }
            },
        },
    )
    update_service_release(
        helm_manager, network_svc, "openstack-neutron", neutron_patch
    )
    wait_for_objects_ready(network_svc, ["neutron-server"])
    LOG.info("Sleeping for 1200 seconds to let neutron process all ports")
    time.sleep(1200)
    LOG.info("Finished waiting neutron server to process OVN ports")


def migrate_dataplane(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    helm_manager = helm.HelmManager(namespace=osdpl.namespace)
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    LOG.info(
        "Pre-migration check: Checking ovs db connectivity in ovn controllers"
    )
    try:
        daemonsets_exec_parallel(
            ovn_daemonsets,
            ["ovs-vsctl", "--no-wait", "list-br"],
            "controller",
            max_workers=script_args.max_workers,
        )
    except Exception as e:
        LOG.error(
            f"Failed Pre-migration check, fix issues and rerun migrate_dataplane stage"
        )
        raise e
    LOG.info("Pre-migration check: Ovs db connectivity check completed")

    for ds in ovn_daemonsets:
        ds.delete(propagation_policy="Foreground")
    wait_for_objects_absent(network_svc, ["ovn-controller"])

    ovs_patch = {
        "conf": {
            "ovn_migration": True,
            "ovn_dataplane_migration": True,
        },
        "manifests": {"daemonset_ovn_controller": True},
    }
    update_service_release(
        helm_manager,
        network_svc,
        "openstack-openvswitch",
        ovs_patch,
    )
    try:
        wait_for_objects_ready(network_svc, ["ovn-controller"], timeout=600)
    except TimeoutError as e:
        LOG.error("Timed out waiting for dataplane migration to complete")
        failed_nodes = set()
        for ds in ovn_daemonsets:
            for pod in ds.pods:
                if not pod.ready:
                    failed_nodes.add(pod.obj["spec"].get("nodeName"))
        LOG.error(f"Found not ready pods on nodes {failed_nodes}")
        raise e


def finalize_migration(script_args):
    osdpl = kube.get_osdpl()
    network_svc = get_service(osdpl, "networking")
    LOG.info("After dataplane migration removing neutron L3 agents")
    neutron_l3_daemonsets = get_objects_by_id(network_svc, "neutron-l3-agent")
    for ds in neutron_l3_daemonsets:
        LOG.info(f"Removing DaemonSet {ds}")
        ds.ensure_finalizer_absent(MIGRATION_FINALIZER)

    LOG.info("Patching Openstack deployment to exit from draft mode")
    osdpl.patch(
        {
            "spec": {
                "draft": False,
                "services": {
                    "networking": {
                        "neutron": {
                            "values": {
                                "manifests": {"deployment_server": True}
                            }
                        },
                        "openvswitch": {
                            "values": {
                                "manifests": {"daemonset_ovn_controller": True}
                            }
                        },
                    }
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    wait_for_objects_ready(
        network_svc,
        [
            "openvswitch-ovn-db",
            "openvswitch-ovn-northd",
        ],
    )

    LOG.info("Switching dataplane from openvswitch pods to ovn pods")
    vswitchd_daemonsets = get_objects_by_id(
        network_svc, "openvswitch-vswitchd"
    )
    ovn_daemonsets = get_objects_by_id(network_svc, "ovn-controller")
    for ovs_ds in vswitchd_daemonsets:
        for ovs_pod in ovs_ds.pods:
            node = ovs_pod.obj["spec"].get("nodeName")
            LOG.info(f"Found ovs pod on node {node}")
            for ovn_ds in ovn_daemonsets:
                if ovn_ds.get_pod_on_node(node):
                    LOG.info(f"Removing ovs pod {ovs_pod} on node {node}")
                    ovs_pod.delete(propagation_policy="Background")
                    LOG.info(f"Updating ovn pod on node {node}")
                    asyncio.run(ovn_ds.ensure_pod_generation_on_node(node))
                    LOG.info(f"Updated ovn pod on node {node}")
                    break
        LOG.info(f"Removing DaemonSet {ovs_ds}")
        ovs_ds.ensure_finalizer_absent(MIGRATION_FINALIZER)

    LOG.info(
        "Disabling migration mode in Osdpl and deploying neutron metadata agent"
    )
    osdpl.patch(
        {
            "spec": {
                "migration": {
                    "neutron": {"ovs_ovn_migration": False},
                },
                "services": {
                    "compute": {
                        "nova": {
                            "values": {
                                "pod": {
                                    "lifecycle": {
                                        "upgrades": {
                                            "daemonsets": {
                                                "pod_replacement_strategy": "RollingUpdate"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "libvirt": {
                            "values": {
                                "pod": {
                                    "lifecycle": {
                                        "upgrades": {
                                            "daemonsets": {
                                                "pod_replacement_strategy": "RollingUpdate"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                    "networking": {
                        "neutron": {
                            "values": {
                                "manifests": {"daemonset_metadata_agent": True}
                            }
                        },
                    },
                },
            }
        }
    )
    # https://mirantis.jira.com/browse/PRODX-42146
    time.sleep(30)
    asyncio.run(osdpl.wait_applied())
    mspec = osdpl.mspec
    child_view = resource_view.ChildObjectView(mspec)
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    asyncio.run(health.wait_services_healthy(osdpl.mspec, osdplst, child_view))


def cleanup(script_args):
    cleanup_api_resources()
    cleanup_linux_netns(script_args)


def run_mariadb_cmd(pod, cmd, timeout=120):
    command = ["/bin/sh", "-c", cmd]
    result = pod.exec(
        command,
        container="mariadb",
        timeout=timeout,
        raise_on_error=True,
    )
    return result


def check_galera_state(expected, pod):
    vars = ",".join(["'" + var + "'" for var in expected.keys()])
    cmd = (
        'mariadb --user=root --password="${MYSQL_DBADMIN_PASSWORD}" '
        f'-N -B -e "SHOW GLOBAL STATUS WHERE Variable_name IN ({vars});"'
    )
    result = run_mariadb_cmd(pod, cmd)
    res_state = set()
    for item in result["stdout"].strip().split("\n"):
        key, value = item.split("\t")
        res_state.add((key, value))
    return res_state.difference(set(expected.items()))


def wait_mariadb_desynced(pod, cluster_size, tries=60, delay=10):
    start = 0
    expected = {
        "wsrep_ready": "ON",
        "wsrep_cluster_status": "Primary",
        "wsrep_local_state_comment": "Donor/Desynced",
        "wsrep_cluster_size": str(cluster_size),
        "wsrep_connected": "ON",
    }
    while start < tries:
        LOG.info("Waiting galera to become Desynced")
        pod.reload()
        if not pod.ready:
            diff = check_galera_state(expected, pod)
            if diff:
                LOG.info(f"Galera is not in expected state, diff is {diff}")
            else:
                LOG.info("Galera cluster member is Desynced.")
                return
        time.sleep(delay)
        start += 1
    raise RuntimeError("Tired waiting for mariadb to be Desynced")


WORKFLOW = [
    {
        "executable": prepare,
        "name": "10_PREPARE",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: No downtime expected.""",
        "description": """
            Check pre-requisites, backup bridge mappings on nodes.""",
    },
    {
        "executable": deploy_ovn_db,
        "name": "20_DEPLOY_OVN_DB",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: Neutron API and Metadata downtime starts in this stage.""",
        "description": """
            Deploy OVN with only database components enabled,
            Disable neutron server, metadata agent and all neutron ovs related components except L3 agents.""",
    },
    {
        "executable": deploy_ovn_controllers,
        "name": "30_DEPLOY_OVN_CONTROLLERS",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: Neutron Metadata downtime continues in this stage.
                           Neutron API is started to process existing ports, however
                           API operations may fail as OVN is not functional yet.""",
        "description": """
            Stop Neutron rabbitmq.
            Deploy OVN controllers in migration mode.
            Sync neutron database with flag migrate to OVN database.
            (requires ovn controllers to be running and ready).
            Start Neutron server.""",
    },
    {
        "executable": migrate_dataplane,
        "name": "40_MIGRATE_DATAPLANE",
        "impact": """
            WORKLOADS: Short periods of downtime ARE EXPECTED.
            OPENSTACK API: Neutron Metadata downtime continues in this stage.""",
        "description": """
            Deploy OVN controller on the same nodes as openvswitch pods are running.
            Switch dataplane to be managed by OVN controller and cleanup old dataplane
            leftovers.""",
    },
    {
        "executable": finalize_migration,
        "name": "50_FINALIZE_MIGRATION",
        "impact": """
            WORKLOADS: Short periods of downtime ARE EXPECTED.
            OPENSTACK API: Neutron Metadata downtime stops in this stage.""",
        "description": """
            Remove neutron l3 agent daemonsets.
            Stop openvswitch pods and disbale migration mode (switch ovn
            controllers to start own vswitchd and ovs db containers).
            Enable Neutron metadata agents and Neutron rabbitmq.""",
    },
    {
        "executable": cleanup,
        "name": "60_CLEANUP",
        "impact": """
            WORKLOADS: No downtime expected.
            OPENSTACK API: No downtime expected.""",
        "description": """
            Cleanup OVS leftovers in Openstack API.
            Remove not used OVS interfaces and linux network namespaces.""",
    },
]


def do_migration(script_args):
    state_cm = StateCM(
        MIGRATION_STATE_CONFIGMAP_NAME,
        settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        WORKFLOW,
    )
    state = state_cm.state
    LOG.info(f"Initial migration state is {state}")
    for stage in WORKFLOW:
        stage_name = stage["name"]
        error = None
        try:
            if state[stage_name]["status"] == COMPLETED:
                LOG.info(
                    f"Stage {stage_name} is already finished, skipping it"
                )
                continue
            LOG.info(
                f"""Running {stage_name} stage
                Description: {stage['description']}
                IMPACT: {stage['impact']}
            """
            )
            state_cm.update(stage_name, STARTED)
            stage["executable"](script_args)
            state_cm.update(stage_name, COMPLETED)
            LOG.info(f"Completed {stage_name} stage")
        except Exception as e:
            error = e
            state_cm.update(stage_name, FAILED, error=traceback.format_exc())
            LOG.exception(f"Failed to run stage {stage_name}")
        finally:
            current_index = WORKFLOW.index(stage)
            if script_args.interactive and current_index != len(WORKFLOW) - 1:
                next_stage = WORKFLOW[current_index + 1]
                LOG.info(
                    f"""Next stage to run is {next_stage['name']}
                        Description: {next_stage['description']}
                        IMPACT: {next_stage['impact']}
                    """
                )
                msg = "To proceed to next stage press Y, to abort WHOLE procedure press N"
                res = check_input(lambda x: x in ["Y", "N"], msg)
                if res == "Y":
                    # Ignoring any errors if user chose to proceed
                    error = None
                elif res == "N":
                    LOG.warning("Aborting execution")
                    break
            if error:
                raise error


def do_preflight_checks():
    ocm = OpenStackClientManager()
    report_file = f"preflight_checks_{time.strftime('%Y%m%d%H%M%S')}.yaml"
    report_path = os.path.join(LOG_DIR, report_file)
    all_reports = {}
    errors = 0
    warnings = 0
    for check_cls in CheckBase.registry.values():
        check = check_cls(ocm.oc)
        all_reports.update(check.run_check())
        if check.status == CheckStatus.ERROR:
            errors += 1
        elif check.status == CheckStatus.WARNING:
            warnings += 1
    with open(report_path, "w") as f:
        yaml.dump(all_reports, f)
    if errors:
        LOG.error(
            f"Found {errors} errors in the check results. "
            f"Please check {report_path} for more details"
        )
        sys.exit(1)
    elif warnings:
        LOG.warning(
            f"Found {warnings} warnings in the check results. "
            f"Please check {report_path} for more details"
        )
    else:
        LOG.info("All checks are successful.")


def do_full_db_backup():
    LOG.info("Backing up database")
    backup_cj_name = "mariadb-phy-backup"
    osdpl = kube.get_osdpl()
    mspec = osdpl.mspec
    backup_enabled = (
        mspec.get("features", {})
        .get("database", {})
        .get("backup", {})
        .get("enabled", False)
    )
    if not backup_enabled:
        LOG.warning(f"Backup database in disabled state")
        return
    cronjob = kube.find(
        kube.CronJob, backup_cj_name, settings.OSCTL_OS_DEPLOYMENT_NAMESPACE
    )
    if cronjob.obj["spec"].get("suspend", False):
        LOG.warning(f"Cronjob {backup_cj_name} in suspended state")
        return
    asyncio.run(
        cronjob.run(wait_completion=True, timeout=MARIADB_FULL_BACKUP_TIMEOUT)
    )
    LOG.info(f"Database backup is completed")


def do_neutron_db_backup():
    osdpl = kube.get_osdpl()
    LOG.info("Backing up Neutron database")
    database_svc = get_service(osdpl, "database")
    database_obj = get_objects_by_id(database_svc, "mariadb-server")[0]
    mariadb_pods = sorted(
        database_obj.pods, key=lambda p: p.name, reverse=True
    )
    # get replica with highest index
    target_pod = mariadb_pods[0]
    cluster_size = int(
        run_mariadb_cmd(target_pod, "echo ${MARIADB_REPLICAS}")[
            "stdout"
        ].strip()
    )
    if cluster_size != len(mariadb_pods):
        raise RuntimeError(
            f"Found {len(mariadb_pods)} mariadb pods, need {cluster_size} to make backup"
        )
    synced_state = {
        "wsrep_ready": "ON",
        "wsrep_cluster_status": "Primary",
        "wsrep_local_state_comment": "Synced",
        "wsrep_cluster_size": str(cluster_size),
        "wsrep_connected": "ON",
    }
    for pod in mariadb_pods:
        diff = check_galera_state(synced_state, pod)
        if diff:
            raise RuntimeError(
                f"Mariadb {pod} is not in expected state {synced_state}"
            )
    asyncio.run(database_obj.wait_ready(timeout=600))
    try:
        LOG.info(f"Desyncing mariadb on {target_pod} from Galera cluster")
        cmd = (
            'mariadb --user=root --password="${MYSQL_DBADMIN_PASSWORD}" '
            '-e "SET GLOBAL wsrep_desync = ON"'
        )
        run_mariadb_cmd(target_pod, cmd)
        wait_mariadb_desynced(target_pod, cluster_size)
        LOG.info(f"Desynced mariadb on {target_pod} from Galera cluster")
        LOG.info(f"Starting Neutron database backup on {target_pod}")
        timestamp = time.strftime("%Y%m%d%H%M%S")
        cmd = (
            'mariadb-dump --user=root --password="${MYSQL_DBADMIN_PASSWORD}" --single-transaction '
            f"--databases neutron --result-file={BACKUP_NEUTRON_DB_PATH}/neutron-ovs-ovn-migration-{timestamp}.sql"
        )
        result = run_mariadb_cmd(
            target_pod, cmd, timeout=MARIADB_NEUTRON_BACKUP_TIMEOUT
        )
        if result["timed_out"]:
            raise RuntimeError(
                f"Neutron db backup exceeded time out {MARIADB_NEUTRON_BACKUP_TIMEOUT} seconds"
            )
        if result["exception"]:
            raise RuntimeError(
                f"Failed to do backup because of exception {result['exception']}"
            )
        LOG.info(f"Neutron database dump on {target_pod} is completed")
    finally:
        LOG.info(f"Syncing mariadb on {target_pod} back to Galera cluster")
        cmd = (
            'mariadb --user=root --password="${MYSQL_DBADMIN_PASSWORD}" '
            '-e "SET GLOBAL wsrep_desync = OFF"'
        )
        run_mariadb_cmd(target_pod, cmd)
        asyncio.run(database_obj.wait_ready(timeout=600))
        LOG.info(f"Synced mariadb on {target_pod} back to Galera cluster")


def main():
    args = set_args()
    global LOG
    global LOG_DIR
    LOG_DIR = args.log_dir
    LOG = get_logger()
    if args.mode == "migration":
        do_migration(args)
    elif args.mode == "preflight_checks":
        do_preflight_checks()
    elif args.mode == "backup_db":
        do_full_db_backup()
        do_neutron_db_backup()


if __name__ == "__main__":
    main()
