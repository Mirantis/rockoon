from enum import IntEnum


class ServiceState(IntEnum):
    up = 1
    down = 0


class ServiceStatus(IntEnum):
    enabled = 1
    disabled = 0


class LoadbalancerStatus(IntEnum):
    ONLINE = 0
    DRAINING = 1
    OFFLINE = 2
    DEGRADED = 3
    ERROR = 4
    NO_MONITOR = 5


class LoadbalancerProvisioningStatus(IntEnum):
    ACTIVE = 0
    DELETED = 1
    ERROR = 2
    PENDING_CREATE = 3
    PENDING_UPDATE = 4
    PENDING_DELETE = 5


BAREMETAL_NODE_PROVISION_STATE = {
    "unknown": 0,
    "enroll": 1,
    "verifying": 2,
    "manageable": 3,
    "available": 4,
    "active": 5,
    "deploy": 6,
    "wait call-back": 7,
    "deploying": 8,
    "deploy failed": 9,
    "deploy complete": 10,
    "deploy hold": 11,
    "deleting": 12,
    "deleted": 13,
    "cleaning": 14,
    "undeploy": 15,
    "clean wait": 16,
    "clean failed": 17,
    "clean hold": 18,
    "error": 19,
    "rebuild": 20,
    "inspecting": 21,
    "inspect failed": 22,
    "inspect wait": 23,
    "adopting": 24,
    "adopt failed": 25,
    "rescue": 26,
    "rescue failed": 27,
    "rescue wait": 28,
    "rescuing": 29,
    "unrescue failed": 30,
    "unrescuing": 31,
    "service": 32,
    "servicing": 33,
    "service wait": 34,
    "service failed": 35,
    "service hold": 36,
}


"Binary giga unit"
Gi = 1024**3


NEUTRON_NETWORK_IP_METRICS_TAG = "openstack.lcm.mirantis.com:prometheus"
