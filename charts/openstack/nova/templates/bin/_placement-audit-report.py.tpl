#!/usr/bin/env python
"""
Generates report in format:
{"orphaned_allocations":
    {"detected": {
        "<resource_provider_uuid>": [
           {"consumer": "<uuid>",
            "resources": {
                "<resource_class1>": <value1>,
                "<resource_class2>": <value2>
                }
            }
        ]
    }
}
Report is uploaded to configmap with appropriate timestamp.
"""
import json
import logging
import os
import re
import sys
import time

import pykube
from retry import retry

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

UUID_PATTERN = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
RESOURCES_PATTERN = r"\{.*\}"
ORPHANED_PATTERN = rf"Allocations for consumer UUID ({UUID_PATTERN}) on Resource Provider ({UUID_PATTERN}) can be deleted: ({RESOURCES_PATTERN})"
REPORT_CONFIGMAP = "nova-placement-audit-report"
NAMESPACE = "openstack"


LOG = logging.getLogger(__name__)


def login():
    config = pykube.KubeConfig.from_env()
    client = pykube.HTTPClient(config, timeout=30)
    LOG.info(f"Created k8s api client from context {config.current_context}")
    return client


K8S_API = login()


@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def create_configmap(data, cm_name, namespace):
    obj = {
        "kind": "ConfigMap",
        "apiVersion": "v1",
        "data": data,
        "metadata": {
            "name": cm_name,
            "namespace": namespace,
        },
    }
    pykube.ConfigMap(K8S_API, obj).create()


@retry(Exception, delay=1, tries=7, backoff=2, logger=LOG)
def get_configmap(cm_name, namespace):
    return (
        pykube.ConfigMap.objects(K8S_API)
        .filter(namespace=namespace)
        .get_or_none(name=cm_name)
    )


@retry(Exception, delay=5, tries=7, backoff=2, logger=LOG)
def update_configmap(cm, data):
    LOG.info(f"Patching configmap {cm.name}")
    cm.reload()
    cm.patch({"data": data})


def save_report(data):
    cm = get_configmap(REPORT_CONFIGMAP, NAMESPACE)
    if not cm:
        LOG.info("Report configmap is not found, creating it")
        create_configmap(data, REPORT_CONFIGMAP, NAMESPACE)
    else:
        LOG.info("Updating report configmap")
        update_configmap(cm, data)


def wait_result(path):
    while not os.path.exists(path):
        time.sleep(15)
    with open(path, "r") as f:
        result = f.read()
        if result != "0":
            LOG.error("Result {result} != 0 in {path}")
            sys.exit(1)


def get_allocations_data(pattern, file_path):
    with open(file_path, "r") as log:
        text = log.read()
    data = re.findall(pattern, text)
    result = {}
    for csm_uuid, rp_uuid, resources in data:
        result.setdefault(rp_uuid, [])
        resources_json = json.loads(resources.replace("'", '"'))
        result[rp_uuid].append(
            {
                "consumer": csm_uuid,
                "resources": resources_json,
            }
        )
    return result


def main():
    audit_report = {"orphaned_allocations": {}}
    wait_result("/tmp/audit_completed")
    detected = get_allocations_data(ORPHANED_PATTERN, "/tmp/audit.log")
    audit_report["orphaned_allocations"]["detected"] = detected
    json_report = json.dumps(audit_report)
    LOG.info(f"Resulting report: {json_report}")
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data = {"report": json_report, "report_ts": ts}
    save_report(data)


main()
