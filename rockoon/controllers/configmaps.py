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
    "configmaps",
    labels={constants.OSDPL_WATCH_LABEL[0]: constants.OSDPL_WATCH_LABEL[1]},
)
@kopf.on.create(
    "",
    "v1",
    "configmaps",
    labels={constants.OSDPL_WATCH_LABEL[0]: constants.OSDPL_WATCH_LABEL[1]},
)
def handle_watch_configmap(
    body,
    meta,
    name,
    status,
    logger,
    diff,
    **kwargs,
):
    LOG.debug(f"Handling configmap create/update {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)
    if not osdpl:
        return

    hasher = hashlib.sha256()
    hasher.update(json.dumps(body["data"], sort_keys=True).encode())
    cm_hash = hasher.hexdigest()

    osdpl.patch(
        {"status": {"watched": {"configmaps": {name: {"hash": cm_hash}}}}},
        subresource="status",
    )


@kopf.on.delete(
    "",
    "v1",
    "configmaps",
    labels={constants.OSDPL_WATCH_LABEL[0]: constants.OSDPL_WATCH_LABEL[1]},
)
def handle_delete_watch_configmap(
    body,
    meta,
    name,
    status,
    logger,
    diff,
    **kwargs,
):
    LOG.debug(f"Handling configmap delete {name}")
    osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)
    if not osdpl:
        return

    osdpl.patch(
        {"status": {"watched": {"configmaps": {name: None}}}},
        subresource="status",
    )
