import kopf
import pykube

from . import constants
from . import kube
from . import layers
from . import utils
from . import settings


LOG = utils.get_logger(__name__)


def _get(namespace, role):
    try:
        return kube.find(
            pykube.DaemonSet, f"{constants.CACHE_NAME}-{role}", namespace
        )
    except pykube.exceptions.PyKubeError:
        return None


def cleanup_legacy_cache(namespace):
    try:
        cache = kube.find(
            pykube.DaemonSet, f"{constants.CACHE_NAME}-0", namespace
        )
        cache.delete()
    except pykube.exceptions.PyKubeError:
        pass


def get_running_images(namespace, role):
    images = {}
    daemon = _get(namespace, role)
    if daemon:
        images.update(
            {
                i["name"].replace("_", "-"): i["image"]
                for i in daemon.obj["spec"]["template"]["spec"]["containers"]
            }
        )
    LOG.debug(f"Checking cached images. {len(images)}")
    return images


def get_expected_images(mspec, role):
    cache_images = set(layers.render_cache_images(role) or [])
    images = {}
    for name, url in layers.render_artifacts(mspec).items():
        images.setdefault(url, []).append(name)
    return {
        names[0].replace("_", "-"): url
        for url, names in images.items()
        if set(names) & cache_images
    }


def ensure(osdpl, mspec):
    namespace = osdpl["metadata"]["namespace"]
    to_wait = []
    # TODO(vsaienko): remove in 25.2
    cleanup_legacy_cache(namespace)
    for role in constants.NodeRole:
        node_selector = settings.OSCTL_OPENSTACK_NODE_LABELS[role]
        role = role.value
        expected_images = get_expected_images(mspec, role)
        running_images = get_running_images(namespace, role)
        cache_ds_name = f"{constants.CACHE_NAME}-{role}"
        if expected_images != running_images:
            LOG.info(f"Starting cache for {role} ...")
            cache = layers.render_cache_template(
                mspec,
                cache_ds_name,
                expected_images,
                node_selector=node_selector,
            )
            kopf.adopt(cache, osdpl)
            res = kube.resource(cache)
            if res and res.exists():
                res.delete()
            res.create()
        else:
            LOG.info(f"Cache for role {role} is in required state.")
        to_wait.append(cache_ds_name)
    for ds_name in to_wait:
        LOG.info(f"Waiting image cache: {ds_name}")
        kube.wait_for_daemonset_ready(ds_name, namespace)
