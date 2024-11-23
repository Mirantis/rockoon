#!/usr/bin/env python

{{/*
Copyright 2020 Miranits Inc.

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

import argparse
import yaml
import logging
import sys
import time

import openstack
import keystoneauth1
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

LOG = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG.setLevel(logging.INFO)

connect_retries =  30
connect_retry_delay = 1

def parse_args():
    parser = argparse.ArgumentParser(description='Create Networking resources')
    parser.add_argument('--resources-file', required=True, help='The path to yaml file with resources.')

    return parser.parse_args()

def _get_raw_client():
    conn = openstack.connect()
    session = conn.session

    adapter = keystoneauth1.adapter.Adapter(
        session=conn.session,
        service_type='network',
        interface='internalURL',
        version='2.0'
    )

    try:
        access_info = adapter.session.auth.get_access(adapter.session)
        access_info.service_catalog.get_endpoints()
    except (AttributeError, ValueError) as e:
        raise e
    return adapter

def _send_request(adapter, method, url, **request_kwargs):
    response = None
    for i in range(connect_retries):
        try:
          response = getattr(adapter, method)(
              url, **request_kwargs)
        except Exception as e:
            if not hasattr(e, 'http_status') or (e.http_status >= 500
                or e.http_status == 0):
                msg = ("Got retriable exception when contacting "
                       "Neutron API. Sleeping for %ss. Attepmpts "
                       "%s of %s")
                LOG.debug(msg)
                time.sleep(connect_retry_delay)
                continue
            raise e
        break
    if not response or not response.content:
        return {}
    try:
        resp = response.json()
    except ValueError:
        resp = response.content
    return resp

NET_ATTR_MAPPING = {
    'name': 'name',
    'mtu': 'mtu',
    'external': 'router:external',
    'network_type': 'provider:network_type',
    'physnet': 'provider:physical_network',
    'segmentation_id': 'provider:segmentation_id',
    'shared': 'shared',
    'description': 'description',
    'is_default': 'is_default',
    'admin_state_up': 'admin_state_up',
    'dns_domain': 'dns_domain',
    'port_security_enabled': 'port_security_enabled',
}

SUBNET_ATTR_MAPPING = {
    'name': 'name',
    'dhcp': 'enable_dhcp',
    'network_id': 'network_id',
    'nameservers': 'dns_nameservers',
    'gateway': 'gateway_ip',
    'range': 'cidr',
    'ip_version': 'ip_version',
}

def _convert_fieds(source, mapping):
    api_object = {}
    for alias, obj_attr in mapping.items():
        if alias in source:
            api_object[obj_attr] = source[alias]
    return api_object


def _get_network_api_object(source):
    return _convert_fieds(source, NET_ATTR_MAPPING)


def _get_subnet_api_object(source, network_id):
    subnet = {}
    subnet['allocation_pools'] = [
        {'start': source['pool_start'],
         'end': source['pool_end']}
    ]
    subnet['network_id'] = network_id
    subnet_obj = _convert_fieds(source, SUBNET_ATTR_MAPPING)
    subnet_obj.update(subnet)
    return subnet_obj

if __name__ == "__main__":
    args = parse_args()
    resources = {}

    with open(args.resources_file, "r") as f:
        resources = yaml.safe_load(f)

    networks = resources.get('networks')

    if networks is None:
        LOG.info('No networks to manage.')
        sys.exit(0)
    adapter = _get_raw_client()

    for name, network in networks.items():
        if not network:
            continue

        name = network.get('name', name)
        network['name'] = name
        LOG.info('Handling network: %s' % name)
        nets = _send_request(adapter, 'get', '/networks?{}'.format(urlencode({'name': name}))).get('networks', {})
        subnets = network.pop('subnets')
        if len(nets) == 0:
            LOG.info('The network is not present, creating...')
            net_obj = _get_network_api_object(network)
            net = _send_request(adapter, 'post', '/networks', json={'network': net_obj}).get('network', {})
        else:
            net = nets[0]
        for name, subnet in subnets.items():
            name = subnet.get('name', name)
            subnet['name'] = name
            LOG.info('Handling subnet %s' % name)
            network_id = net['id']
            subs = _send_request(adapter, 'get', '/subnets?{}'.format(urlencode({'name': name}))).get('subnets', {})
            if len(subs) == 0:
                LOG.info('The subnet is not present, creating...')
                subnet_obj = _get_subnet_api_object(subnet, network_id)
                subs = _send_request(adapter, 'post', '/subnets', json={'subnet': subnet_obj}).get('subnet', {})
