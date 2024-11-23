import json
import kopf
import hashlib

from rockoon import ceph_api
from rockoon import kube
from rockoon import settings  # noqa
from rockoon import utils

LOG = utils.get_logger(__name__)


@kopf.on.resume(
    "",
    "v1",
    "secrets",
)
@kopf.on.update(
    "",
    "v1",
    "secrets",
)
def handle_ceph_shared_secret(
    body,
    meta,
    name,
    status,
    logger,
    diff,
    **kwargs,
):
    if name != ceph_api.OPENSTACK_KEYS_SECRET:
        return
    LOG.debug(f"Handling secret create/update {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)

    hasher = hashlib.sha256()
    hasher.update(json.dumps(body["data"], sort_keys=True).encode())
    secret_hash = hasher.hexdigest()

    osdpl.patch(
        {"status": {"watched": {"ceph": {"secret": {"hash": secret_hash}}}}},
        subresource="status",
    )
