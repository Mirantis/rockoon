#!/usr/bin/env python

import logging
import os
import sys
import time

import pykube
import openstack
from retry import retry

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(os.environ["HOSTNAME"])
LOG.setLevel("INFO")

CLOUD_CALL_RETRIES = int(os.getenv("CLOUD_CALL_RETRIES", 200))

def get_env_var(env_var, default=None):
    if env_var in os.environ:
        return os.environ[env_var]

    if default is not None:
        return default

    LOG.critical(f"environment variable {env_var} not set")
    raise RuntimeError("FATAL")

CINDER_INTERNAL_TENANT_CONFIGMAP="cinder-internal-tenant-ids"
CINDER_NAMESPACE=get_env_var("CINDER_NAMESPACE")


def retry_cloud_call(times, interval=3):
    def decorator(func):
        def newfn(*args, **kwargs):
            attempt = 0
            while attempt < times:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # If http exception with code > 500 or 0 retry
                    if hasattr(e, "http_status") and (
                        e.http_status >= 500 or e.http_status == 0
                    ):
                        attempt += 1
                        LOG.exception(
                            f"Exception thrown when attempting to run {func}, attempt {attempt} of {times}"
                        )
                        time.sleep(interval)
                    else:
                        raise e
            return func(*args, **kwargs)

        return newfn

    return decorator


def log_info(func):
    def wrapper(*args, **kwargs):
        LOG.info("Applying %s: %s ...", args[1].__name__, args[2]["name"])
        result = func(*args, **kwargs)
        LOG.info("  Done [%s=%s]", result.name, result.id)
        return result

    return wrapper


PROJECT_DOMAIN_ID = get_env_var("PROJECT_DOMAIN_ID", 'Default')
INTERNAL_PROJECT_NAME =  get_env_var("INTERNAL_PROJECT_NAME")
INTERNAL_USER_NAME = get_env_var("INTERNAL_USER_NAME")

kube = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)

OS_CLOUD = get_env_var("OS_CLOUD", "envvars")
osc = openstack.connection.Connection(cloud=OS_CLOUD)


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def get_kube(klass, name, namespace):
    return klass.objects(kube).filter(namespace=namespace).get_or_none(name=name)


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def ensure_kube_resource(klass, data, name, namespace):
    ensure = "update" if get_kube(klass, name, namespace) else "create"
    getattr(klass(kube, data), ensure)()


@log_info
@retry_cloud_call(CLOUD_CALL_RETRIES)
def ensure_openstack_resource(find, create, attrs):
    return find(attrs["name"]) or create(**attrs)


@retry_cloud_call(CLOUD_CALL_RETRIES)
def find_user(name, domain_id):
    res = [
        x for x in osc.list_users(domain_id=domain_id) if x.name == name
    ]
    if res:
        return res[0]

# Project domain
project_domain_def = {
    "name": PROJECT_DOMAIN_ID,
}

project_domain = osc.identity.find_domain(PROJECT_DOMAIN_ID)

user_project_def = {
    "name": INTERNAL_PROJECT_NAME,
    "domain_id": project_domain.id,
}

user_project = ensure_openstack_resource(
    osc.identity.find_project, osc.identity.create_project, user_project_def
)


user_def = {
    "name": INTERNAL_USER_NAME,
    "domain_id": project_domain.id,
    "default_project_id": user_project.id,
}


LOG.info("Applying create_user ...")
user = find_user(
    user_def["name"], domain_id=user_def["domain_id"]
) or osc.identity.create_user(**user_def)


LOG.info("Applying configmap %s ...", CINDER_INTERNAL_TENANT_CONFIGMAP)
settings = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": CINDER_INTERNAL_TENANT_CONFIGMAP,
        "namespace": CINDER_NAMESPACE,
        "ownerReferences": [
            {
                "apiVersion": "v1",
                "name": "cinder-bin",
                "kind": "ConfigMap",
                "controller": True,
                "uid": get_kube(pykube.ConfigMap, "cinder-bin", CINDER_NAMESPACE).obj[
                    "metadata"
                ]["uid"],
            }
        ],
    },
    "data": {
        "CINDER_INTERNAL_TENANT_PROJECT_ID": user_project.id,
        "CINDER_INTERNAL_TENANT_USER_ID": user.id,
    },
}

ensure_kube_resource(
    pykube.ConfigMap, settings, CINDER_INTERNAL_TENANT_CONFIGMAP, CINDER_NAMESPACE
)
