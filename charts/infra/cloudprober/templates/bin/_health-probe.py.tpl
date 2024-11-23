#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time

from openstack_discovery import DEFAULT_CONFIG_FILE, get_config

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
LOG = logging.getLogger(__file__)


def check_resource_discovery(res_conf, interval):
    hash_file = f"{res_conf['output_file']}.sha"
    delta = time.time() - os.path.getmtime(hash_file)
    # TODO: each res_type can have its own interval in future
    if delta > interval:
        LOG.error(
            f"Hash file {hash_file} was updated too long ago, something went wrong with discovery"
        )
        sys.exit(1)


parser = argparse.ArgumentParser(description="Process liveness probe arguments")
parser.add_argument(
    "--config-file",
    help="Path to discovery configuration file",
    default=DEFAULT_CONFIG_FILE,
)

args = parser.parse_args()

config = get_config(args.config_file)
enabled_resources = config["enabled_resource_types"]

if not enabled_resources:
    sys.exit(0)

for res_type in enabled_resources:
    check_resource_discovery(config[res_type], config["interval"])
