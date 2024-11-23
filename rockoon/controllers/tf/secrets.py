import json
import kopf
import hashlib

from rockoon import constants
from rockoon import kube
from rockoon import settings  # noqa
from rockoon import utils

LOG = utils.get_logger(__name__)


@kopf.on.update(
    "",
    "v1",
    "secrets",
    labels={constants.TF_OST_DATA_LABEL[0]: constants.TF_OST_DATA_LABEL[1]},
)
@kopf.on.create(
    "",
    "v1",
    "secrets",
    labels={constants.TF_OST_DATA_LABEL[0]: constants.TF_OST_DATA_LABEL[1]},
)
def handle_tf_shared_secrets(
    body,
    meta,
    name,
    status,
    logger,
    diff,
    **kwargs,
):
    LOG.debug(f"Handling secret create/update {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)
    if not osdpl:
        return

    hasher = hashlib.sha256()
    hasher.update(json.dumps(body["data"], sort_keys=True).encode())
    secret_hash = hasher.hexdigest()

    osdpl.patch(
        {"status": {"watched": {"tf": {"secret": {"hash": secret_hash}}}}},
        subresource="status",
    )
