#!/usr/bin/env python3

import os

from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl import utils as osctl_utils
from rockoon import utils
from rockoon import kube
from rockoon import settings

LOG = utils.get_logger(__name__)


class CinderObjectsCollector(base.BaseLogsCollector):
    name = "cinder"

    @osctl_utils.generic_exception
    def collect_ceph_general_info(self):
        LOG.info(f"Starting ceph general info collection")
        pod = kube.find(
            kube.Pod,
            name="cinder-volume-0",
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            silent=True,
        )
        if pod is None or not pod.exists():
            return

        ceph_configs = pod.exec(
            command=["ls", "/etc/ceph"], container="cinder-volume"
        )["stdout"]
        keyrings = [
            conf
            for conf in ceph_configs.splitlines()
            if conf.endswith(".keyring")
        ]
        if not keyrings:
            return
        keyring_name = keyrings[0].replace("ceph.", "").replace(".keyring", "")
        LOG.info(f"Starting ceph info collection.")
        base_dir = os.path.join(self.workspace, "ceph")
        ceph_generic_info = [
            ("ceph_status.txt", ["ceph", "-n", keyring_name, "status"]),
            ("ceph_df.txt", ["ceph", "-n", keyring_name, "df"]),
        ]
        for dst, command in ceph_generic_info:
            self.dump_exec_result(
                os.path.join(base_dir, dst),
                pod.exec(command=command, container="cinder-volume"),
            )
        LOG.info(f"Finished ceph info collection.")

    @property
    def can_run(self):
        if self.mode == "trace":
            LOG.warning("Can't use cinder collector in trace mode.")
            return False
        return True

    def get_tasks(self):
        res = []
        if "cinder" in self.components:
            res.append((self.collect_ceph_general_info, (), {}))
        return res
