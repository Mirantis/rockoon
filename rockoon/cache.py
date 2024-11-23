import kopf
import pykube

from . import constants
from . import kube
from . import layers
from . import utils


LOG = utils.get_logger(__name__)


def _get(namespace, i):
    try:
        return kube.find(
            pykube.DaemonSet, f"{constants.CACHE_NAME}-{i}", namespace
        )
    except pykube.exceptions.PyKubeError:
        return None


def _list(namespace):
    return kube.resource_list(
        pykube.DaemonSet, {"k8s-app__in": {"image-precaching"}}, namespace
    )


def images(namespace):
    images = {}
    daemons = _list(namespace)
    for ds in daemons:
        images.update(
            {
                i["name"].replace("image-precaching-", ""): i["image"]
                for i in ds.obj["spec"]["template"]["spec"]["containers"]
            }
        )
    LOG.debug(
        f"Checking cached images. Daemons inspected: {len(daemons)}, images found: {len(images)}"
    )
    return images


def restart(images, osdpl, mspec):
    namespace = osdpl["metadata"]["namespace"]
    log_showed = False
    for ds in _list(namespace):
        ds.delete()
        if not log_showed:
            LOG.info("Stopping cache ...")
            log_showed = True
        # TODO(avolkov): wait for delete completion
    image_groups = []
    if not images:
        LOG.info("No images to cache. Skip caching")
    else:
        image_list = list(images.items())
        # NOTE(avolkov): images_per_daemon determines how many
        #   daemonsets start depending on total number of images we
        #   need to cache.
        images_per_daemon = 50
        image_groups = [
            dict(image_list[i : i + images_per_daemon])
            for i in range(0, len(image_list), images_per_daemon)
        ]
        LOG.info(
            f"Starting cache (images: {len(images)}, instances: {len(image_groups)}) ..."
        )
        for i in range(len(image_groups)):
            cache = layers.render_cache_template(
                mspec, f"{constants.CACHE_NAME}-{i}", image_groups[i]
            )
            kopf.adopt(cache, osdpl)
            kube.resource(cache).create()
    return len(image_groups)


def wait_ready(namespace):
    for ds in _list(namespace):
        kube.wait_for_daemonset_ready(ds.obj["metadata"]["name"], namespace)
