#!/usr/bin/env python3

import os
import json

from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl import utils as osctl_utils
from rockoon import utils
from rockoon import kube
from rockoon import settings

LOG = utils.get_logger(__name__)


class NeutronObjectsCollector(base.BaseLogsCollector):
    name = "neutron"

    @osctl_utils.generic_exception
    def collect_namespaces_info(self, host):
        kube_api = kube.kube_client()
        selector = {"application": "neutron", "component": "l3-agent"}
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector=selector,
            field_selector={"spec.nodeName": host},
        )
        pods = [pod for pod in pods]
        if not pods:
            return
        pod = pods[0]
        namespaces = pod.exec(
            command=["ip", "-j", "netns", "list"], container=None
        )["stdout"]
        if namespaces:
            namespaces = json.loads(namespaces)
        base_dir = os.path.join(self.workspace, host)
        ip_generic_info = [
            ("ip_addr.txt", ["ip", "addr"]),
            ("ip_link.txt", ["ip", "-d", "link", "show"]),
            ("ip_nei.txt", ["ip", "nei", "show"]),
        ]
        iptables_info = [
            ("iptables_filter.txt", ["iptables", "-nvL"]),
            ("iptables_nat.txt", ["iptables", "-nvL", "-t", "nat"]),
            ("ip_nei.txt", ["ip", "nei", "show"]),
        ]
        generic_info = [
            ("ip_netns_list.txt", ["ip", "netns", "list"]),
        ]
        for dst, command in generic_info + ip_generic_info:
            self.dump_exec_result(
                os.path.join(base_dir, dst),
                pod.exec(command=command, container=None),
            )

        for namespace in namespaces or []:
            netns = namespace["name"]
            for dst, netns_cmd in ip_generic_info + iptables_info:
                command = ["ip", "netns", "exec", netns] + netns_cmd
                self.dump_exec_result(
                    os.path.join(base_dir, netns, dst),
                    pod.exec(command=command, container=None),
                )

    @osctl_utils.generic_exception
    def collect_ovs_info(self, host):
        kube_api = kube.kube_client()
        ovs_container = "openvswitch-vswitchd"
        selector = {
            "application": "openvswitch",
            "component": "openvswitch-vswitchd",
        }
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector=selector,
            field_selector={"spec.nodeName": host},
        )
        pods = [pod for pod in pods]
        if not pods:
            return
        pod = pods[0]
        base_dir = os.path.join(self.workspace, host)
        ovs_generic_info = [
            ("ovsdb_client_dump.txt", ["ovsdb-client", "dump"]),
            (
                "ovsdb_client_dump.json",
                ["ovsdb-client", "--format", "json", "dump"],
            ),
            (
                "ovs_vsctl_list_interface.txt",
                ["ovs-vsctl", "list", "interface"],
            ),
            ("ovs_vsctl_show.txt", ["ovs-vsctl", "show"]),
            (
                "ovs_dpctl_dump_flows.txt",
                ["ovs-dpctl", "-m", "--names", "-s", "dump-flows"],
            ),
            (
                "ovs_dpctl_show.txt",
                ["ovs-dpctl", "-m", "--names", "-s", "show"],
            ),
            ("ovs_appctl_dpif_show.txt", ["ovs-appctl", "dpif/show"]),
            ("ovs_coverage_show.txt", ["ovs-appctl", "coverage/show"]),
        ]
        for dst, command in ovs_generic_info:
            self.dump_exec_result(
                os.path.join(base_dir, dst),
                pod.exec(command=command, container=ovs_container),
            )
        bridges = pod.exec(
            command=["ovs-vsctl", "list-br"], container=ovs_container
        )["stdout"]
        for bridge in bridges.strip().splitlines():
            bridge_info = [
                (
                    "ovs_ofctl_dump_flows.txt",
                    [
                        "ovs-ofctl",
                        "-O",
                        "OpenFlow14",
                        "dump-flows",
                        bridge,
                    ],
                ),
                (
                    "ovs_appctl_dump_flows.txt",
                    ["ovs-appctl", "bridge/dump-flows", bridge],
                ),
            ]
            for dst, command in bridge_info:
                self.dump_exec_result(
                    os.path.join(base_dir, bridge, dst),
                    pod.exec(command=command, container=ovs_container),
                )

    @property
    def can_run(self):
        if self.mode == "trace":
            LOG.warning("Can't use neutron collector in trace mode.")
            return False
        return True

    def get_tasks(self):
        res = []
        if "neutron" in self.components:
            for host in self.hosts:
                res.append((self.collect_ovs_info, (host,), {}))
                res.append((self.collect_namespaces_info, (host,), {}))
        return res
