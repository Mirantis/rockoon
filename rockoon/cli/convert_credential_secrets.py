#!/usr/bin/env python3
import pykube

from rockoon import kube
from rockoon import constants
from rockoon import settings

import base64
import json
import logging
import sys

namespace = settings.OSCTL_OS_DEPLOYMENT_NAMESPACE

logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


def convert_structure(src):
    data = {}
    value = base64.b64decode(src).decode()
    creds = json.loads(value)
    for item in creds:
        data[item["account"]] = {
            "username": item["username"],
            "password": item["password"],
        }
    value = json.dumps(data)
    return base64.b64encode(value.encode()).decode()


def main():
    for os_service_name in constants.OS_SERVICES_MAP:
        LOG.info(f"Process secrets for {os_service_name} service.")
        src_secret_name = f"{os_service_name}-service-accounts"
        src_secret = kube.find(pykube.Secret, src_secret_name, namespace, True)
        if src_secret:
            dst_secret_name = f"generated-{os_service_name}-passwords"
            dst_secret = kube.find(pykube.Secret, dst_secret_name, namespace)
            dst_secret.obj["data"]["identity"] = convert_structure(
                src_secret.obj["data"][os_service_name]
            )
            dst_secret.update()
            src_secret.delete()
            LOG.info(f"The secret {dst_secret_name} has been removed.")
        else:
            LOG.info(
                f"Secret {src_secret_name} for service is not found. Skip convertation."
            )


if __name__ == "__main__":
    main()
