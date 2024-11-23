#!/usr/bin/env python3

import logging
import os
import pykube
import sys

from retry import retry

application = "cinder"
namespace = os.getenv("NAMESPACE")

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config=config, timeout=30)
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


def getObjects(klass, api, components):
    objects = klass.objects(api).filter(
        namespace=namespace,
        selector={'application__in':{application}, 'component__in':components}
    )
    return [obj for obj in objects]


@retry(Exception, delay=1, max_delay=15, backoff=2, logger=LOG)
def waitForReady(backend):
    backend.reload()

    backendKind = backend.obj["kind"]
    if backendKind not in ["StatefulSet", "DaemonSet"]:
        LOG.info(f"Skipping unknown backend type {backendKind}")
        return

    if (
        backend.obj["status"]["observedGeneration"]
        < backend.obj["metadata"]["generation"]
    ):
        raise Exception(f"Generation for {backend.name} is not updated yet.")

    backendStatus = backend.obj.get("status", {})
    ready = desired = updated = None
    backendUpdateStrategy = backend.obj["spec"].get("updateStrategy", {}).get("type")
    if backendKind == "StatefulSet":
        ready = backendStatus.get('readyReplicas', 0)
        desired = backend.obj["spec"]["replicas"]
        updated = backendStatus.get('updatedReplicas', 0)
    else:
        ready = backendStatus.get('numberReady', 0)
        desired = backendStatus.get('desiredNumberScheduled', 0)
        updated = backendStatus.get('updatedNumberScheduled', 0)

    if backendUpdateStrategy == "OnDelete":
        if ready != desired:
            raise Exception(f"The {backend.name} is not ready yet.")
    else:
        if not (ready == desired and ready == updated):
            raise Exception(f"The {backend.name} is not ready yet.")


api = login()
backendsForCheck = getObjects(pykube.StatefulSet, api, {"volume"})
backendsForCheck.extend(getObjects(pykube.DaemonSet, api, {"volume_daemonset"}))

for backend in backendsForCheck:
    LOG.info(f"Checking backend {backend.name}")
    waitForReady(backend)

LOG.info(f"All Cinder backends are ready.")
