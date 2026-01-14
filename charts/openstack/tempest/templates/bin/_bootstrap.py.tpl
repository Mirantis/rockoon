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

import configparser
import logging
import openstack
import sys
from packaging.version import Version
from retry import retry
from urllib.parse import urlencode

CONFIG_FILE = "/etc/tempest/tempest.conf"

cfg = configparser.ConfigParser(strict=False)
cfg.read(CONFIG_FILE)

# ENTRYPOINT
ost = openstack.connect()

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


# The OpenstackSDK version we are using does not support DNS.tlds so we do
# direct API calls for operations with tlds
@retry(
    openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG
)
def tld_query(method, tld_name):
    LOG.info(f"Process {method.upper()} to DNS API ...")
    if method.lower() == "get":
        response = ost.dns.get(f"/tlds?{urlencode({'name': tld_name})}")
    elif method.lower() == "post":
        response = ost.dns.post(
            "/tlds",
            json={"name": tld_name, "description": "tempest-tests"}
        )
    if response.status_code >= 500:
        raise openstack.exceptions.SDKException(
            f"Query finished with code {response.status_code}.\n{response.text}"
        )
    elif response.status_code >= 400:
        raise Exception(
            f"Query finished with code {response.status_code}.\n{response.text}"
        )
    LOG.info(f"  Done")
    return response.json()


@retry(
    openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG
)
def ensure_openstack_resource(find, create, attrs):
    LOG.info(f"Applying {create.__name__} ...")
    result = find(attrs["name"]) or create(**attrs)
    LOG.info(f"  Done [{result.name} = {result.id}]")
    return result


@retry(
    openstack.exceptions.SDKException, delay=1, tries=7, backoff=2, logger=LOG
)
def query_with_retry(method, args):
    LOG.info(f"Execute {method.__name__} ...")
    result = method(**args)
    LOG.info("  Done")
    return result


public_network_name = cfg.get(
    "heat_plugin",
    "floating_network_name",
    fallback=cfg.get("network", "floating_network_name", fallback=None),
)
if not public_network_name:
    raise Exception("Failed to detect public_network name.")

public_network_id = query_with_retry(
    ost.network.find_network,
    {
        "name_or_id": public_network_name,
    },
)["id"]


network_id = ensure_openstack_resource(
    ost.network.find_network,
    ost.network.create_network,
    {"name": "heat-net"},
)["id"]

subnet_id = ensure_openstack_resource(
    ost.network.find_subnet,
    ost.network.create_subnet,
    {
        "name": "heat-subnet",
        "network_id": network_id,
        "ip_version": "4",
        "cidr": "10.20.30.0/24",
        "is_dhcp_enabled": "true",
        "gateway_ip": "10.20.30.1",
        "allocation_pools": [
            {
                "start": "10.20.30.10",
                "end": "10.20.30.254",
            }
        ],
    },
)["id"]

router_id = ensure_openstack_resource(
    ost.network.find_router,
    ost.network.create_router,
    {
        "name": "heat-router",
        "external_gateway_info": {"network_id": public_network_id},
    },
)["id"]

router_ports = query_with_retry(
    ost.network.ports,
    {"device_id": router_id},
)

found = False
for port in router_ports:
    for ips in port["fixed_ips"]:
        if ips["subnet_id"] == subnet_id:
            found = True
            break
    if found:
        break
else:
    query_with_retry(
        ost.network.add_interface_to_router,
        {
            "router": router_id,
            "subnet_id": subnet_id,
        },
    )


if cfg.get("service_available", "contrail", fallback="false").lower() == "true":
    tf_network_id = ensure_openstack_resource(
        ost.network.find_network,
        ost.network.create_network,
        {
            "name": "tempest-fixed-net",
            "shared": "true",
        },
    )["id"]

    ensure_openstack_resource(
        ost.network.find_subnet,
        ost.network.create_subnet,
        {
            "name": "tempest-subnet",
            "network_id": tf_network_id,
            "ip_version": "4",
            "cidr": "10.20.40.0/24",
            "is_dhcp_enabled": "true",
            "gateway_ip": "10.20.40.1",
            "allocation_pools": [
                {
                    "start": "10.20.40.10",
                    "end": "10.20.40.254",
                }
            ],
        },
    )
else:
    ensure_openstack_resource(
        ost.network.find_subnet_pool,
        ost.network.create_subnet_pool,
        {
            "name": "default_pool",
            "is_default": "true",
            "shared": "true",
            "prefixes": ["10.20.40.0/24"],
            "default_prefixlen": 26,
        },
    )


if (
    cfg.get("service_available", "designate", fallback="false").lower() == "true"
    and cfg.get("DEFAULT", "production", fallback="true").lower() == "false"
    and Version(cfg.get("compute", "max_microversion", fallback="2.00")) > Version("2.90")
):
    for tld in [cfg.get("dns", "tld_suffix"), "arpa", "in-addr.arpa"]:
        output = tld_query("get", tld)["tlds"]
        if output:
            result = output[0]
        else:
            result = tld_query("post", tld)
        LOG.info(f"  DNS TLD [{tld} = {result['id']}]")
