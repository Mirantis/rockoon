#!/usr/bin/env python3
import pykube
import requests

from rockoon import kube
from rockoon import settings
from rockoon import utils

LOG = utils.get_logger("remove-legacy-finalizer")

LEGACY_KOPF_FINALIZER = "lcm.mirantis.com/openstack-controller"


def main():
    for kclass_name in [
        "StatefulSet",
        "DaemonSet",
        "Deployment",
        "NodeMaintenanceRequest",
        "ClusterMaintenanceRequest",
        "NodeWorkloadLock",
        "NodeDisableNotification",
        "Node",
        "OpenStackDeployment",
    ]:
        kclass = getattr(kube, kclass_name)
        namespace = settings.OSCTL_OS_DEPLOYMENT_NAMESPACE
        if not issubclass(kclass, pykube.objects.NamespacedAPIObject):
            namespace = None
        try:
            for obj in kube.resource_list(
                kclass, selector=None, namespace=namespace
            ):
                LOG.info(
                    f"Checking finalizer for {kclass.__name__}: {obj.metadata['name']}"
                )
                for finalizer in obj.metadata.get("finalizers", []):
                    if finalizer.startswith(LEGACY_KOPF_FINALIZER):
                        LOG.info(
                            f"Removing legacy finalizer {finalizer} for {kclass.__name__}: {obj.metadata['name']}"
                        )
                        finalizers = obj.metadata["finalizers"]
                        finalizers.remove(finalizer)
                        obj.patch({"metadata": {"finalizers": finalizers}})
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                LOG.info(
                    f"Resource {kclass.__name__} does not exists. Skipping."
                )
                continue
            LOG.error("Unknonw exception occured")
            raise
