"""
This file contains api shared with OS Controller
"""

from dataclasses import asdict, dataclass
from enum import Enum, auto
from ipaddress import IPv4Address
from typing import Tuple, Iterable, Iterator, Callable, Dict, List, Any

from dacite import from_dict

from rockoon import settings
from rockoon.utils import to_base64, from_base64


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


class OSUser(Enum):
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
class OSPoolCreds:
    user: OSUser
    role: PoolRole
    creds: PoolCreds


@dataclass
class PoolDescription:
    device_class: str
    role: PoolRole
    name: str


@dataclass
class OSServiceCreds:
    user: OSUser
    key: str
    key_name: str
    pools: List[PoolDescription]


@dataclass
class RGWParams:
    internal_url: str
    external_url: str


@dataclass
class OSCephParams:
    admin_user = "client.admin"
    admin_key: str
    mon_endpoints: List[Tuple[IPv4Address, int]]
    services: List[OSServiceCreds]
    rgw: RGWParams = None


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


def get_os_user_keyring_name(user: OSUser) -> str:
    return f"{user.name}-rbd-keyring"


def _os_ceph_params_to_secret(params: OSCephParams) -> Dict[str, str]:
    data = {
        params.admin_user: params.admin_key,
        "mon_endpoints": to_base64(_pack_ips(params.mon_endpoints)),
        "rgw_internal": to_base64(params.rgw.internal_url),
        "rgw_external": to_base64(params.rgw.external_url),
    }

    for service in params.services:
        pools: List[str] = [service.key_name, service.key]
        for pool in service.pools:
            pools.append(f"{pool.name}:{pool.role.name}:{pool.device_class}")
        data[service.user.name] = to_base64(";".join(pools))

    return data


def _os_ceph_params_from_secret(secret: Dict[str, str]) -> OSCephParams:
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
        rgw = RGWParams(
            internal_url=from_base64(rgw_internal),
            external_url=from_base64(rgw_external),
        )

    services: List[OSServiceCreds] = []
    for os_user, val in local_secret.items():
        # NOTE(vsaienko): do not handle unknow keys for pools.
        if os_user not in CEPH_POOL_ROLE_SERVICES_MAP:
            continue
        key_name, key, *pools_descr = from_base64(val).split(";")

        pools: List[PoolDescription] = []
        for pool_info in pools_descr:
            name, role, dev_cls = pool_info.split(":")
            pools.append(
                PoolDescription(
                    name=name,
                    role=PoolRole[role],
                    device_class=dev_cls,
                )
            )

        services.append(
            OSServiceCreds(
                user=OSUser[os_user], key_name=key_name, key=key, pools=pools
            )
        )

    return OSCephParams(
        admin_key=admin_key,
        mon_endpoints=mon_endpoints,
        services=services,
        rgw=rgw,
    )


def _pack_ips(ips_and_ports: Iterable[Tuple[IPv4Address, int]]) -> str:
    return ",".join(f"{ip}:{port}" for ip, port in ips_and_ports)


def _unpack_ips(data: str) -> Iterator[Tuple[IPv4Address, int]]:
    for itm in data.split(","):
        ip, port = itm.split(":")
        yield IPv4Address(ip), int(port)


def get_os_ceph_params(
    read_secret: Callable[[str, str], Dict[str, str]],
) -> OSCephParams:
    """Get OpenStack Ceph parameters
    Returns OpenStack Ceph parameters from secret OPENSTACK_KEYS_SECRET in shared ceph namespace
    :param read_secret: function to read secret, have to return secret['data'] dictionary
                        with base64 keys
    :returns: OSCephParams object
    """
    return _os_ceph_params_from_secret(
        read_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE, OPENSTACK_KEYS_SECRET
        )
    )


def set_os_ceph_params(
    os_params: OSCephParams,
    save_secret: Callable[[str, str, Dict[str, str]], Any],
) -> None:
    save_secret(
        settings.OSCTL_CEPH_SHARED_NAMESPACE,
        OPENSTACK_KEYS_SECRET,
        _os_ceph_params_to_secret(os_params),
    )


def get_os_rgw_creds(
    read_secret: Callable[[str, str], Dict[str, str]],
) -> OSRGWCreds:
    return from_dict(
        OSRGWCreds,
        read_secret(
            settings.OSCTL_CEPH_SHARED_NAMESPACE, OPENSTACK_RGW_SECRET
        ),
    )


def set_os_rgw_creds(
    os_rgw_creds: OSRGWCreds,
    save_secret: Callable[[str, str, Dict[str, str]], Any],
) -> None:
    save_secret(
        settings.OSCTL_CEPH_SHARED_NAMESPACE,
        OPENSTACK_RGW_SECRET,
        asdict(os_rgw_creds),
    )
