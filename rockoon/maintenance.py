import datetime
import logging
import threading

import enum
import json
import pykube
import kopf

from rockoon import constants as const
from rockoon import kube
from rockoon.utils import merger
from rockoon import settings

LOG = logging.getLogger(__name__)
CONF = settings.CONF
MAINTENANCE_LOCK = threading.Lock()

MAINTENANCE_DEFAULT_NODE_CONFIG = {
    # The migration mode for instances present on the host either
    # live, manual or skip.
    # *live - oc will try to automatically live migrate instances
    # TODO(vsaienko): NOT IMPLEMENTED *live+cold - oc will try to automatically live migrate instances, in case of failure fallback to cold migration
    # TODO(vsaienko): NOT IMPLEMENTED 0*cold - oc will do cold migration for instances
    # *manual - oc do not touch instances, wait while they will be migrated manually.
    # *skip - do not call migration for instances, release lock and allow host reboot.
    "instance_migration_mode": {"default": "live", "type": "string"},
    # The number of attempts we trying to migrate instance before give up.
    "instance_migration_attempts": {"default": "3", "type": "int"},
}


# Maximum number of nodes upgraded in parallel.
def get_max_parallel_by_role(role):
    return {
        const.NodeRole.controller.value: 1,
        const.NodeRole.gateway.value: CONF.getint(
            "maintenance", "nwl_parallel_max_gateway"
        ),
        const.NodeRole.compute.value: CONF.getint(
            "maintenance", "nwl_parallel_max_compute"
        ),
    }[role]


class NodeMaintenanceConfig:
    opts_prefix = "openstack.lcm.mirantis.com"

    def __init__(self, node):
        self.node = node
        self._initialize_maintenance_opts()

    def _cast_to_type(self, value, type):
        if type == "string":
            return str(value)
        if type == "int":
            return int(value)
        if type == "bool":
            value = value.lower()
            if value in const.TRUE_STRINGS:
                return True
            elif value in const.FALSE_STRINGS:
                return False
        raise TypeError(
            f"Failed to process option value: {value} with type: {type}"
        )

    def _initialize_maintenance_opts(self):
        self.node.reload()
        for opt_name, opt in MAINTENANCE_DEFAULT_NODE_CONFIG.items():
            annotation_name = f"{self.opts_prefix}/{opt_name}"
            opt_val = self.node.metadata["annotations"].get(
                annotation_name, opt["default"]
            )
            value = self._cast_to_type(opt_val, type=opt["type"])
            setattr(self, opt_name, value)


class LockState(enum.Enum):
    active = "active"
    inactive = "inactive"
    failed = "failed"


class LockInnerState(enum.Enum):
    active = "active"  # We are progressing with the node
    inactive = "inactive"  # We finished with the node


class MaintenanceRequestScope(enum.Enum):
    drain = "drain"  # drain pods, no os reboot
    os = "os"  # include drain + potential os reboot


class LockBase(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    workload = "openstack"

    @classmethod
    def dummy(cls, name):
        dummy = {
            "apiVersion": cls.version,
            "kind": cls.kind,
            "metadata": {
                "name": name,
                "annotations": {},
            },
            "spec": {"controllerName": cls.workload},
        }
        return dummy

    @classmethod
    def get_by_name(cls, name):
        kube_api = kube.kube_client()
        obj = kube.find(cls, name, silent=True)
        if obj and obj.exists():
            return obj
        return cls(kube_api, cls.dummy(name))

    def present(self):
        if not self.exists():
            self.create()
            # Explicitly set state to active to do not rely on default.
            self.set_state(LockState.active.value)
        else:
            merger.merge(self.obj, self.dummy(self.name))
            self.update()
        if settings.OSCTL_CLUSTER_RELEASE:
            # NOTE(vsaienko): reset cwl to active if it was set to inactive
            # by previous controller. PRODX-22757
            if self.get_release() != settings.OSCTL_CLUSTER_RELEASE:
                self.set_state(LockState.active.value)
                self.set_release(settings.OSCTL_CLUSTER_RELEASE)

    def absent(self, propagation_policy=None):
        if self.exists():
            self.delete(propagation_policy=propagation_policy)

    def is_active(self):
        self.reload()
        return self.obj["status"]["state"] == LockState.active.value

    def is_maintenance(self):
        self.reload()
        return self.get_inner_state() == LockInnerState.active.value

    def set_state(self, state):
        self.patch({"status": {"state": state}}, subresource="status")

    def set_state_active(self):
        self.set_state(LockState.active.value)

    def set_release(self, release):
        self.patch({"status": {"release": release}}, subresource="status")

    def get_release(self):
        self.reload()
        return self.obj["status"].get("release", None)

    def set_state_inactive(self):
        self.set_state(LockState.inactive.value)

    def set_inner_state(self, state):
        self.patch({"metadata": {"annotations": {"inner_state": state}}})

    def set_inner_state_active(self):
        self.set_inner_state(LockInnerState.active.value)

    def set_inner_state_inactive(self):
        self.set_inner_state(LockInnerState.inactive.value)

    def get_inner_state(self):
        return self.obj["metadata"].get("annotations", {}).get("inner_state")

    def set_error_message(self, msg):
        timestamp = datetime.datetime.utcnow()
        msg = f"{timestamp} {msg}"
        self.patch({"status": {"errorMessage": msg}}, subresource="status")

    def unset_error_message(self):
        self.patch({"status": {"errorMessage": None}}, subresource="status")


class ClusterWorkloadLock(LockBase):
    endpoint = "clusterworkloadlocks"
    kind = "ClusterWorkloadLock"

    @classmethod
    def get_by_osdpl(cls, osdpl_name):
        return cls.get_by_name(f"{cls.workload}-{osdpl_name}")


class NodeWorkloadLock(LockBase):
    """The NodeWorkloadLock object

    Should be present for each node that we care about
      - openstack application is present on the node

    When removed triggers openstack metadata removal.
    """

    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodeworkloadlocks"
    kind = "NodeWorkloadLock"
    kopf_on_args = *version.split("/"), endpoint

    @classmethod
    def dummy(cls, name):
        node_name = "-".join(name.split("-")[1:])
        dummy = super().dummy(name)
        dummy["spec"]["nodeName"] = node_name
        dummy["spec"]["nodeDeletionRequestSupported"] = True
        node = kube.safe_get_node(node_name)
        if node.exists():
            node = node.obj
            node.pop("status", None)
            dummy["metadata"]["annotations"].update(
                {"openstack.lcm.mirantis.com/original-node": json.dumps(node)}
            )
        return dummy

    @classmethod
    def get_by_node(cls, node_name):
        return cls.get_by_name(f"{cls.workload}-{node_name}")

    @staticmethod
    def required_for_node(node_name: str) -> bool:
        """Do we need to keep NodeWorkloadLock for specified node."""
        node = kube.safe_get_node(node_name)
        return node.has_os_role()

    @classmethod
    def get_all(cls):
        kube_api = kube.kube_client()
        return [
            o
            for o in cls.objects(kube_api)
            if o.obj["spec"]["controllerName"] == cls.workload
        ]

    def maintenance_locks(self):
        locks = {role.value: [] for role in const.NodeRole}
        for nwl in self.get_all():
            if nwl.is_maintenance():
                node = kube.safe_get_node(nwl.obj["spec"]["nodeName"])
                if node.exists():
                    for role in const.NodeRole:
                        if node.has_role(role):
                            locks[role.value].append(nwl)
        return locks

    def can_handle_nmr(self):
        """Check if we can handle more NodeMaintenanceRequests

        Compare current number of active NodeMaintenanceRequests with
        maximum allowed number of parallel nodes.

        return: False if can't handle additional request. True othervise.
        """
        active_locks = self.maintenance_locks()
        for role, locks in active_locks.items():
            len_locks = len(locks)
            if len_locks >= get_max_parallel_by_role(role):
                node_name = self.obj["spec"]["nodeName"]
                LOG.info(
                    f"Handling Nodemaintenancerequest for node {node_name} is not allowed. Already handling {locks} for role: {role}"
                )
                return False
        return True

    def acquire_internal_lock(self):
        """Acquire internal lock on workloadlock object

        Set internal state to active, which basically means that we start
        handling the node, but did not change state of workloadlock to active.
        Should be done under lock to avoid races with parallel nmr handling.

        :raises TemporaryError: when can't handle nmr due to cuncurrent operations.
        """
        with MAINTENANCE_LOCK:
            if not self.is_maintenance() and not self.can_handle_nmr():
                node_name = self.obj["spec"]["nodeName"]
                msg = (
                    f"Number of inactive NodeWorkloadLocks exceeds allowed concurrency. "
                    f"Deferring processing for node {node_name}"
                )
                self.set_error_message(msg)
                raise kopf.TemporaryError(msg)
            self.set_inner_state_active()


class MaintenanceRequestBase(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"

    @classmethod
    def get_resource(cls, data):
        kube_api = kube.kube_client()
        return cls(kube_api, data)

    def get_scope(self):
        return self.obj["spec"]["scope"]

    def is_reboot_possible(self):
        return self.get_scope() == MaintenanceRequestScope.os.value


class NodeMaintenanceRequest(MaintenanceRequestBase):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodemaintenancerequests"
    kind = "NodeMaintenanceRequest"
    kopf_on_args = *version.split("/"), endpoint


class ClusterMaintenanceRequest(MaintenanceRequestBase):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "clustermaintenancerequests"
    kind = "ClusterMaintenanceRequest"
    kopf_on_args = *version.split("/"), endpoint


class NodeDeletionRequest(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodedeletionrequests"
    kind = "NodeDeletioneRequest"
    kopf_on_args = *version.split("/"), endpoint


class NodeDisableNotification(pykube.objects.APIObject):
    version = "lcm.mirantis.com/v1alpha1"
    endpoint = "nodedisablenotifications"
    kind = "NodeDisableNotification"
    kopf_on_args = *version.split("/"), endpoint


def find_ndn(node_name):
    kube_api = kube.kube_client()
    for ndn in NodeDisableNotification.objects(kube_api):
        if ndn.obj["spec"]["nodeName"].split(".")[0] == node_name:
            return ndn
