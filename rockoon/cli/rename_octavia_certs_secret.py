#!/usr/bin/env python3
from rockoon import kube
from rockoon import settings
from rockoon import utils

LOG = utils.get_logger("rename-octavia-certs-secret")

DEPRECATED_SECRET_NAME = "octavia-certs"
NEW_SECRET_NAME = "generated-octavia-amphora-certs"


def main():
    namespace = settings.OSCTL_OS_DEPLOYMENT_NAMESPACE

    deprecated_secret = kube.find(
        kube.Secret,
        name=DEPRECATED_SECRET_NAME,
        namespace=namespace,
        silent=True,
    )

    new_secret = kube.find(
        kube.Secret,
        name=NEW_SECRET_NAME,
        namespace=namespace,
        silent=True,
    )

    if deprecated_secret and not new_secret:
        LOG.info(
            f"Found deprecated secret {DEPRECATED_SECRET_NAME} and {NEW_SECRET_NAME} does not exist. Renaming..."
        )

        data = deprecated_secret.obj["data"]
        kube.save_secret_data(
            namespace=namespace,
            name=NEW_SECRET_NAME,
            data=data,
        )
        deprecated_secret.delete()
        LOG.info(
            f"Secret {DEPRECATED_SECRET_NAME} successfully renamed to {NEW_SECRET_NAME}."
        )
    else:
        LOG.info("No action required.")
