#!/usr/bin/env python3

import os

from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl import utils as osctl_utils
from rockoon import utils
from rockoon import kube
from rockoon import settings

LOG = utils.get_logger(__name__)


class NovaObjectsCollector(base.BaseLogsCollector):
    name = "nova"

    @osctl_utils.generic_exception
    def collect_instances_info(self, host):
        kube_api = kube.kube_client()
        LOG.info(f"Starting instance info collection for {host}")
        selector = {"application": "libvirt", "component": "libvirt"}
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector=selector,
            field_selector={"spec.nodeName": host},
        )
        pods = [pod for pod in pods]
        if not pods:
            return

        pod = pods[0]
        instances = pod.exec(
            command=["virsh", "list", "--name"], container="libvirt"
        )["stdout"]
        LOG.info(f"Starting instance info collection for {host}")
        base_dir = os.path.join(self.workspace, host)
        libvirt_generic_info = [
            ("instances.txt", ["virsh", "list", "--name"]),
            ("nodecpumap.txt", ["virsh", "nodecpumap"]),
            ("nodecpustats.txt", ["virsh", "nodecpustats"]),
            ("nodeinfo.txt", ["virsh", "nodeinfo"]),
            ("nodememstats.txt", ["virsh", "nodememstats"]),
            ("sysinfo.txt", ["virsh", "sysinfo"]),
            ("version.txt", ["virsh", "version"]),
            ("capabilities.txt", ["virsh", "capabilities"]),
        ]
        for dst, command in libvirt_generic_info:
            self.dump_exec_result(
                os.path.join(base_dir, dst),
                pod.exec(command=command, container="libvirt"),
            )

        for instance in instances.strip().splitlines():
            domain_info = [
                ("dumpxml.txt", ["virsh", "dumpxml", instance]),
                ("domiflist.txt", ["virsh", "domiflist", instance]),
                ("domblklist.txt", ["virsh", "domblklist", instance]),
                ("error.txt", ["/bin/foo", "domblklist", instance]),
            ]
            for dst, command in domain_info:
                self.dump_exec_result(
                    os.path.join(base_dir, instance, dst),
                    pod.exec(command=command, container="libvirt"),
                )
        LOG.info(f"Finished instance info collection for {host}")

    @property
    def can_run(self):
        if self.mode == "trace":
            LOG.warning("Can't use nova collector in trace mode.")
            return False
        return True

    def get_tasks(self):
        res = []
        if "nova" in self.components:
            for host in self.hosts:
                res.append((self.collect_instances_info, (host,), {}))
        return res
