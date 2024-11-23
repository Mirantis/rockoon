#!/usr/bin/env python3

"""
Nginx ingress configuration initialization script

The script is responsible for initiation of nginx ingress config map.
The nginx ingress reloads its configuration at runtime, when we change
sensitive settings like tls listen or bind address it may harm a lot as
old instances (that were not restarted) pick up configuration without
restart simulteniously. This script is intended to preserve nginx ingress
configuration and make sure it is updated only when pod is restarted.

Env variables:
INGRESS_CONFIG_MAP_NAMESPACE: The namespace where to look for configmaps
INGRESS_SOURCE_CONFIG_MAP:    The name of source config map to use
INGRESS_CONFIG_MAP_HASH:      The hash of current ingress config map. Used as a suffix to build
                              target config map <INGRESS_SOURCE_CONFIG_MAP>-<INGRESS_CONFIG_MAP_HASH>

Changelog:
0.1.0: Initial varsion
"""


import logging
import os
import sys

import pykube

INGRESS_CONFIG_MAP_NAMESPACE = os.getenv("INGRESS_CONFIG_MAP_NAMESPACE")
INGRESS_SOURCE_CONFIG_MAP = os.getenv("INGRESS_SOURCE_CONFIG_MAP")
INGRESS_CONFIG_MAP_HASH = os.getenv("INGRESS_CONFIG_MAP_HASH")
INGRESS_TARGET_CONFIG_MAP = f"{INGRESS_SOURCE_CONFIG_MAP}-{INGRESS_CONFIG_MAP_HASH}"
INGRESS_CONFIG_MAP_HASH_LABEL = "ingress-config-hash"


log_level = "DEBUG"
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("ingress-config-init")

LOG.setLevel(log_level)


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config=config, timeout=30)
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


API = login()


def cleanup_metadata(obj):
    # cleanup the object of runtime stuff
    obj.obj.pop("status", None)
    obj.obj["metadata"].pop("creationTimestamp", None)
    obj.obj["metadata"].pop("resourceVersion", None)
    obj.obj["metadata"].pop("selfLink", None)
    obj.obj["metadata"].pop("uid", None)


def ensure_target_configmap(namespace: str, src_name: str, dst_name: str):
    LOG.info(f"Ensure target config map exists {dst_name}")
    src_cm = pykube.ConfigMap.objects(API).filter(namespace=namespace).get_or_none(name=src_name)
    if not src_cm or not src_cm.exists():
        raise Exception(f"Could not find source configuration {src_name}")
    dst_cm = pykube.ConfigMap.objects(API).filter(namespace=namespace).get_or_none(name=dst_name)
    if dst_cm and dst_cm.exists():
        LOG.info(f"Target configuration {dst_name} exists. Skipping creation.")
        return

    dst_cm = src_cm
    dst_cm.reload()
    cleanup_metadata(dst_cm)

    dst_cm.obj["metadata"]["labels"][INGRESS_CONFIG_MAP_HASH_LABEL] = INGRESS_CONFIG_MAP_HASH
    dst_cm.obj["metadata"]["name"] = dst_name
    try:
        dst_cm.create()
    except pykube.exceptions.HTTPError as e:
        if "already exists" in str(e):
            LOG.info(f"Target configuration {dst_name} exists. Skipping creation.")
        else:
            raise e


def remove_stale_configmaps(namespace: str, pod_label: str):
    LOG.info("Checking for stale config maps")
    used_hashes = set([INGRESS_CONFIG_MAP_HASH])
    for pod in pykube.Pod.objects(API).filter(
        namespace=namespace, selector={"application__in": ["ingress"], "component__in": ["server"]}
    ):
        used_config_hash = pod.obj["metadata"]["labels"].get(INGRESS_CONFIG_MAP_HASH_LABEL)
        if used_config_hash:
            used_hashes.add(used_config_hash)
    LOG.info(f"Used hashes are {used_hashes}")

    for cm in pykube.ConfigMap.objects(API).filter(namespace=namespace):
        cm_config_hash = cm.obj["metadata"].get("labels", {}).get(INGRESS_CONFIG_MAP_HASH_LABEL)
        if cm_config_hash and cm_config_hash not in used_hashes:
            LOG.info(f"Removing stale config map {cm.name}")
            cm.delete()


def main():
    ensure_target_configmap(INGRESS_CONFIG_MAP_NAMESPACE, INGRESS_SOURCE_CONFIG_MAP, INGRESS_TARGET_CONFIG_MAP)
    remove_stale_configmaps(INGRESS_CONFIG_MAP_NAMESPACE, INGRESS_CONFIG_MAP_NAMESPACE)


main()
