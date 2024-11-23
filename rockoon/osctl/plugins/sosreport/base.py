#!/usr/bin/env python3
import abc
import os

from rockoon import kube
from rockoon.osctl.plugins import constants


class BaseLogsCollector:
    name = ""
    registry = {}

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        cls.registry[cls.name] = cls

    def __init__(self, args, workspace, mode):
        self.args = args
        self.workspace = os.path.join(workspace, self.name)
        self.mode = mode
        self.hosts = self.get_hosts()
        self.components = self.get_components()

    def get_hosts(self):
        hosts = set()

        kube_client = kube.kube_client()

        if self.args.all_hosts:
            for host in kube.Node.objects(kube_client):
                hosts.add(host.name)
            return hosts

        for host_pattern in set(self.args.host):
            if "=" in host_pattern:
                selector = {}
                for selector_pattern in host_pattern.split(","):
                    label, value = selector_pattern.split("=")
                    selector.update({label: value})
                for host in kube.Node.objects(kube_client).filter(
                    selector=selector
                ):
                    hosts.add(host.name)
            else:
                hosts.add(host_pattern)
        return hosts

    def get_components(self):
        if self.args.all_components:
            return set(constants.OSCTL_COMPONENT_LOGGERS.keys())
        return set(self.args.component)

    def dump_exec_result(self, dst, res):
        os.makedirs(os.path.dirname(dst), exist_ok=True)

        if res.get("stdout"):
            with open(dst, "w") as f:
                f.write(res["stdout"])
        if res.get("stderr"):
            with open(f"{dst}.error", "w") as f:
                f.write(res["stderr"])

    @abc.abstractmethod
    def get_tasks(self):
        """Returns tuple with task and arguments for logs collection."""
        pass

    @property
    def can_run(self):
        """Returns True when using collector in current configuration is possible"""
        return True
