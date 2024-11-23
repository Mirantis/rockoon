#!/usr/bin/env python3
{{/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

import logging
import openstack
import json
import sys
from retry import retry

NETWORK = json.loads({{ toJson .Values.bootstrap.floating_network | quote }})
NETWORK_SUBNET = NETWORK["subnet"]
NETWORK_ROUTER = NETWORK["router"]
NETWORK_OPTIONS_MAPPING = {
    "name": "name",
    "external": "is_router_external",
    "network_type": "provider_network_type",
    "physnet": "provider_physical_network",
    "segmentation_id": "provider_segmentation_id",
    "default": "is_default",
}

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


def log_info(func):
    def wrapper(*args, **kwargs):
        LOG.info("Applying %s ...", args[1].__name__)
        result = func(*args, **kwargs)
        LOG.info("  Done [%s=%s]", result.name, result.id)
        return result

    return wrapper


@log_info
@retry(openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG)
def ensure_openstack_resource(find, create, attrs):
    return find(attrs["name"]) or create(**attrs)


# ENTRYPOINT
ost = openstack.connect()

network_id = ensure_openstack_resource(
    ost.network.find_network,
    ost.network.create_network,
    {
        NETWORK_OPTIONS_MAPPING[k]: v
        for k, v in NETWORK.items()
        if k in NETWORK_OPTIONS_MAPPING
    },
)["id"]

ensure_openstack_resource(
    ost.network.find_subnet,
    ost.network.create_subnet,
    {
        "name": NETWORK_SUBNET["name"],
        "network_id": network_id,
        "ip_version": "4",
        "cidr": NETWORK_SUBNET["range"],
        "is_dhcp_enabled": NETWORK_SUBNET["dhcp"],
        "gateway_ip": NETWORK_SUBNET["gateway"],
        "allocation_pools": [
            {
                "start": NETWORK_SUBNET["pool_start"],
                "end": NETWORK_SUBNET["pool_end"],
            }
        ],
    },
)

ensure_openstack_resource(
    ost.network.find_router,
    ost.network.create_router,
    {
        "name": NETWORK_ROUTER["name"],
        "external_gateway_info": {"network_id": network_id},
    },
)
