"""
This file contains api shared with OS Controller
"""

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from enum import Enum, auto
from ipaddress import IPv4Address
import json
from typing import Any, Self

from rockoon import settings
from rockoon.utils import from_base64

OPENSTACK_KEYS_SECRET = "openstack-ceph-keys"
OPENSTACK_RGW_SECRET = "openstack-rgw-creds"

CEPH_OPENSTACK_TARGET_SECRET = "rook-ceph-admin-keyring"
CEPH_OPENSTACK_TARGET_CONFIGMAP = "rook-ceph-config"

CEPH_POOL_ROLE_SERVICES_MAP = {
    "cinder": ["volumes", "backup"],
    "nova": ["ephemeral", "vms"],
    "glance": ["images"],
    "manila": [],
}


class OSService(Enum):
    nova = auto()
    cinder = auto()
    glance = auto()
    manila = auto()


class PoolRole(Enum):
    ephemeral = auto()
    volumes = auto()
    backup = auto()
    images = auto()
    rgw = auto()
    kubernetes = auto()
    vms = auto()
    other = auto()


class PoolCreds(Enum):
    read = auto()
    read_write = auto()


@dataclass
class PoolDescription:
    device_class: str
    role: PoolRole
    name: str

    @classmethod
    def from_str(cls, pool_info: str) -> Self:
        name, role, dev_cls = pool_info.split(":")
        return cls(name=name, role=PoolRole[role], device_class=dev_cls)

    def __repr__(self):
        return f"Ceph pool={self}"

    def __str__(self):
        return f"{self.name}:{self.role.name}:{self.device_class}"


@dataclass
class CephUser:
    client_id: str  # short name, like nova123, used in OpenStack configs
    client_name: str  # full name, like client.nova123, used in Ceph configs
    key: str  # base64-encoded auth key


@dataclass
class OSServiceCreds:
    service: OSService  # OpenStack service that uses these creds
    ceph_user: CephUser
    pools: list[PoolDescription]


@dataclass
class RGWParams:
    internal_url: str
    external_url: str
    internal_cacert: str | None = None
    metrics_user_secret_key: str | None = None
    metrics_user_access_key: str | None = None


@dataclass
class OSCephParams:
    # NOTE: admin ceph auth is currently only used in:
    # - parts of ceph-rgw chart that we do not ever deploy
    # - some helm-toolkit functions related to S3 buckets - do we need them?
    admin_key: str
    mon_endpoints: list[tuple[IPv4Address, int]]
    services: list[OSServiceCreds]
    rgw: RGWParams | None = None
    admin_user: str = "client.admin"


class CephStatus:
    waiting = "waiting"
    created = "created"


@dataclass
class OSRGWCreds:
    auth_url: str
    default_domain: str
    interface: str
    password: str
    project_domain_name: str
    project_name: str
    region_name: str
    user_domain_name: str
    username: str
    ca_cert: str
    public_domain: str
    tls_crt: str
    tls_key: str
    barbican_url: str


def get_os_service_user_keyring_name(service: OSService) -> str:
    return f"{service.name}-rbd-keyring"


def _os_ceph_params_from_secret(secret: dict[str, str]) -> OSCephParams:
    local_secret = secret.copy()
    admin_key = local_secret.pop(OSCephParams.admin_user)
    mon_endpoints = list(
        _unpack_ips(from_base64(local_secret.pop("mon_endpoints")))
    )
    rgw = None

    # NOTE(vsaienko): pop fields not represent pools always.
    rgw_internal = local_secret.pop("rgw_internal", None)
    rgw_external = local_secret.pop("rgw_external", None)
    if rgw_internal and rgw_external:
        rgw_kwargs = {
            "internal_url": from_base64(rgw_internal),
            "external_url": from_base64(rgw_external),
        }
        for key in [
            "internal_cacert",
            "metrics_user_secret_key",
            "metrics_user_access_key",
        ]:
            val = local_secret.pop(f"rgw_{key}", None)
            if val:
                rgw_kwargs[key] = from_base64(val)

        rgw = RGWParams(**rgw_kwargs)

    services: list[OSServiceCreds] = []
    for os_service, val in local_secret.items():
        # NOTE(vsaienko): do not handle unknow keys for pools.
        if os_service not in CEPH_POOL_ROLE_SERVICES_MAP:
            continue
        val = from_base64(val)
        try:
            parsed = json.loads(val)
            pools_descr = parsed.pop("pools", [])
            ceph_user = CephUser(**parsed)
        except json.JSONDecodeError:
            client_name, key, *pools_descr = val.split(";")
            ceph_user = CephUser(
                client_id=os_service,
                client_name=client_name,
                key=key,
            )

        pools = [PoolDescription.from_str(p) for p in pools_descr]

        services.append(
            OSServiceCreds(
                service=OSService[os_service], ceph_user=ceph_user, pools=pools
            )
        )

    return OSCephParams(
        admin_key=admin_key,
        mon_endpoints=mon_endpoints,
        services=services,
        rgw=rgw,
    )


def _unpack_ips(data: str) -> Iterator[tuple[IPv4Address, int]]:
    for itm in data.split(","):
        ip, port = itm.split(":")
        yield IPv4Address(ip), int(port)


def wait_for_ceph_secret(waiter: Callable[[str, str], Any]) -> None:
    waiter(settings.OSCTL_CEPH_SHARED_NAMESPACE, OPENSTACK_KEYS_SECRET)


def get_os_ceph_params(
    read_secret: Callable[[str, str], dict[str, str]],
) -> OSCephParams:
    """Get OpenStack Ceph parameters

    Returns OpenStack Ceph parameters from secret OPENSTACK_KEYS_SECRET
    in the shared ceph namespace.
    :param read_secret: function to read secret, have to return secret['data']
                        dictionary with base64 keys
    :returns: OSCephParams object
    """
    return _os_ceph_params_from_secret(
        read_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE, OPENSTACK_KEYS_SECRET
        )
    )


def set_os_rgw_creds(
    os_rgw_creds: OSRGWCreds,
    save_secret: Callable[[str, str, dict[str, str]], Any],
) -> None:
    save_secret(
        settings.OSCTL_CEPH_SHARED_NAMESPACE,
        OPENSTACK_RGW_SECRET,
        asdict(os_rgw_creds),
    )
