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
"""
import json
import logging
import os
import re
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

LOG = logging.getLogger(__name__)

UUID_PATTERN = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
RESOURCES_PATTERN = r"\{.*\}"
ORPHANED_PATTERN = rf"Allocations for consumer UUID ({UUID_PATTERN}) on Resource Provider ({UUID_PATTERN}) can be deleted: ({RESOURCES_PATTERN})"


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


audit_report = {"orphaned_allocations": {}}
wait_result("/tmp/audit_completed")
detected = get_allocations_data(ORPHANED_PATTERN, "/tmp/audit.log")
audit_report["orphaned_allocations"]["detected"] = detected
print(json.dumps(audit_report))
