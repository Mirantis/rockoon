#!/usr/bin/env python
import logging
import os
import yaml
import json

import urllib

import requests

KEYSTONE_FEDERATIONS_CONFIG = os.environ.get(
    "KEYSTONE_FEDERATIONS_CONFIG", "/etc/keystone/federation.yaml"
)
KEYSTONE_FEDERATIONS_METADATA_DIR = os.environ.get(
    "KEYSTONE_FEDERATIONS_METADATA_DIR", "/var/www/federation_metadata"
)

LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s"
logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATEFMT)
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def get_metadata_file(issuer, config_type):
    fname = issuer.removeprefix("https://").removeprefix("http://").removesuffix("/")
    filename = urllib.parse.quote_plus(f"{fname}.{config_type}")
    return os.path.join(KEYSTONE_FEDERATIONS_METADATA_DIR, filename)


def get_url_content(url):
    return requests.get(url, timeout=10, verify=False).json()


def main():
    # Mask permissions to files 0640 dirs 0750
    os.umask(0o027)

    with open(KEYSTONE_FEDERATIONS_CONFIG, "r") as f:
        federations_data = yaml.safe_load(f)

    for provider_name, provider in federations_data["openid"]["providers"].items():
        LOG.info("Handling provider %s", provider_name)
        issuer = provider["issuer"]
        for config_type in ["client", "conf"]:
            config = provider["metadata"][config_type]
            config_file = get_metadata_file(issuer, config_type)
            with open(config_file, "w") as f:
                json.dump(config, f)

        if provider["metadata"].get("provider"):
            config = {}
            if "value_from" in provider["metadata"]["provider"]:
                url = provider["metadata"]["provider"]["value_from"]["from_url"]["url"]
                config_file = get_metadata_file(issuer, "provider")
                config = get_url_content(url)
            else:
                config = provider["metadata"]["provider"]
            with open(config_file, "w") as f:
                json.dump(config, f)

        LOG.info("Finished handling provider %s", provider_name)
    LOG.info("Finished metadata files initialization.")


if __name__ == "__main__":
    main()
