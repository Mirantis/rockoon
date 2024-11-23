#!/usr/bin/env python3

import os
import yaml

from rockoon.osctl.plugins.sosreport import base
from rockoon.osctl import utils as osctl_utils
from rockoon import utils
from rockoon import kube

LOG = utils.get_logger(__name__)


class K8sObjectsCollector(base.BaseLogsCollector):
    name = "k8s"

    def __init__(self, args, workspace, mode):
        super().__init__(args, workspace, mode)
        self.objects = {
            "openstack": {
                "PersistentVolumeClaim",
                "Deployment",
                "DaemonSet",
                "StatefulSet",
                "Pod",
                "Job",
                "OpenStackDeployment",
                "OpenStackDeploymentStatus",
            },
            "openstack-redis": {
                "PersistentVolumeClaim",
                "Deployment",
                "StatefulSet",
                "Pod",
                "Job",
            },
            "osh-system": {
                "Deployment",
                "Pod",
                "Job",
            },
            None: {
                "Node",
                "PersistentVolume",
                "ClusterWorkloadLock",
                "NodeWorkloadLock",
                "ClusterMaintenanceRequest",
                "NodeMaintenanceRequest",
            },
        }

    @osctl_utils.generic_exception
    def collect_objects(self):
        kube_api = kube.kube_client()
        for namespace, kinds in self.objects.items():
            base_dir = os.path.join(self.workspace, "cluster")
            if namespace is not None:
                base_dir = os.path.join(
                    self.workspace, "namespaced", namespace
                )
            for kind in kinds:
                work_dir = os.path.join(base_dir, kind.lower())
                os.makedirs(work_dir, exist_ok=True)
                kube_class = kube.get_object_by_kind(kind)
                if kube_class is None:
                    LOG.warning(
                        f"Kind: {kind} is not present in the cluster. Skip objects collection."
                    )
                    continue
                for obj in (
                    kube_class.objects(kube_api).filter(namespace=namespace)
                    or []
                ):
                    dst = os.path.join(work_dir, obj.name)
                    with open(dst, "w") as f:
                        yaml.dump(obj.obj, f)

    @property
    def can_run(self):
        if self.mode == "trace":
            LOG.warning("Can't use k8s collector in trace mode.")
            return False
        return True

    def get_tasks(self):
        res = []
        res.append((self.collect_objects, (), {}))
        return res
