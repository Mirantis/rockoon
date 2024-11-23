#!/usr/bin/env python3

import hashlib
import logging
import os
import sys
import pykube
from jinja2 import Environment, BaseLoader
from retry import retry

# In case if environment variable is set but contains an empty string,
# use the default instead of empty value
def get_var(name, default=''):
    value = os.environ.get(name) or None
    return value or default


DESIGNATE_NAMESPACE = get_var("DESIGNATE_NAMESPACE")
DESIGNATE_POWERDNS_EXTERNAL_SERVICE = get_var("DESIGNATE_POWERDNS_EXTERNAL_SERVICE")
DESIGNATE_POOL_MANAGE_HASH_CONFIG_MAP = "designate-pool-manage-hash"
DESIGNATE_POOL_YAML_TEMPLATE = "/tmp/pools.yaml.template"
DESIGNATE_POOL_YAML_FILE = "/tmp/pools.yaml"
DESIGNATE_POOL_SYNC_FLAG_FILE = "/tmp/skip_pool_update"


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)
KUBE_API = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def get_kube(klass, name, namespace):
    return klass.objects(KUBE_API).filter(namespace=namespace).get_or_none(name=name)

@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def get_external_ip():
    external_svc = get_kube(pykube.Service, DESIGNATE_POWERDNS_EXTERNAL_SERVICE, DESIGNATE_NAMESPACE)
    external_svc.reload()
    for ingress in external_svc.obj["status"].get("loadBalancer", {}).get("ingress", []):
        if ingress.get("ip"):
            return ingress["ip"]
    raise Exception("External IP not found for service {DESIGNATE_POWERDNS_EXTERNAL_SERVICE}")


def render_template(parameters):
    data = None
    with open(DESIGNATE_POOL_YAML_TEMPLATE, "r") as f:
        template = f.read()
        rtemplate = Environment(loader=BaseLoader).from_string(template)
        data = rtemplate.render(**parameters)

    with open(DESIGNATE_POOL_YAML_FILE, "w") as f:
        f.write(data)

    hasher = hashlib.sha256()
    hasher.update(data.encode("utf-8"))
    return hasher.hexdigest()


LOG.info("Getting external powerdns service ip.")
external_ip = get_external_ip()
LOG.info(f"External ip for powerdns service is {external_ip}")

hash_current = render_template({"POWERDNS_SVC_EXTERNAL_IP": external_ip})
hash_old = None
hash_configmap = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": DESIGNATE_POOL_MANAGE_HASH_CONFIG_MAP,
        "namespace": DESIGNATE_NAMESPACE,
        "ownerReferences": [
            {   
                "apiVersion": "v1",
                "name": "designate-bin",
                "kind": "ConfigMap",
                "controller": True,
                "uid": get_kube(pykube.ConfigMap, "designate-bin", DESIGNATE_NAMESPACE).obj[
                    "metadata"
                ]["uid"],
            }
        ],
    },
    "data": {} 
}
hash_configmap_obj = pykube.ConfigMap(KUBE_API, hash_configmap)
if hash_configmap_obj.exists():
    hash_configmap_obj.reload()
    hash_old = hash_configmap_obj.obj.get("data", {}).get("pools.yaml.sha256")
else:
    hash_configmap_obj.create()
    LOG.info("Created hash config map.")

hash_configmap_obj.obj["data"] = {"pools.yaml.sha256": hash_current}
hash_configmap_obj.update()
LOG.info("Updated hash config map.")

if hash_old != hash_current:
    LOG.info(f"Hash for pools.yaml is changed {hash_old} {hash_current}")
else:
    with open(DESIGNATE_POOL_SYNC_FLAG_FILE, 'w') as f:
        pass
    LOG.info("Added skip sync file")
LOG.info("All done")
