#!/usr/bin/env python3
"""
  The script allows to discover various Openstack workloads endpoints
and generates targets file for Cloudprober in json format.

Script requires next configuration files:
 - Discovery configuration file (default "/etc/cloudprober/openstack-discovery.yaml").
   Path to the file can be provided by --config parameter.
 - Clouds.yaml file for connection details when connecting to openstack.
   Path to the file should be set in discovery configuration file.

  Discovery configuration file should be in yaml format. Script supports
filtering of instances by tags. Currently only instance floating ips are
discovered.

  Generated targets file is being provided to cloudprober only when its content
has changed, to minimize number of file reloads by Cloudprober.
Cloudprober uses file modification time as criteria for reloading targets.
Targets file has the next format:
    {"resource":
        [
            {"ip": "<instance_port_ip>",
             "name": "<instance_uuid>-<instance_port_ip>",
             "labels":
                {"openstack_project_id": "<instance_project_id>",
                 "openstack_hypervisor_hostname": "<instance_host_hostname>",
                 "openstack_instance_name": "<instance_name>",
                 "openstack_instance_id": "<instance_uuid>",
                 "openstack_int_type": "<instance_interface_type>"
                }
            }
        ]
    }

Changelog:
0.1.0: Initial version
"""

import argparse
import hashlib
import json
import logging
import sys
import time
import yaml

from openstack.cloud import meta
import openstack.exceptions
from retry import retry

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)
DEFAULT_CONFIG_DIR = "/etc/cloudprober"
DEFAULT_TARGETS_DIR = f"{DEFAULT_CONFIG_DIR}/targets.d"
DEFAULT_CONFIG_FILE = f"{DEFAULT_CONFIG_DIR}/openstack-discovery.yaml"

_retry_options = {
    'delay': 1, 'tries': 7, 'backoff': 2, 'logger': LOG}


class ServerNotFoundError(Exception):
    name_or_id = property(lambda self: self.args[0])

    def __init__(self, name_or_id):
        super().__init__(name_or_id)

    def __str__(self):
        return 'Server lookup by ID {!r} have failed'.format(self.name_or_id)


@retry(openstack.exceptions.SDKException, **_retry_options)
def get_servers(all_projects=False, filters=None):
    LOG.debug(
        'Get severs list: all_project=%r, filters=%s', all_projects, filters)
    filters = filters or {}
    # set bare to true to avoid extra queries to cloud api
    return osc.list_servers(all_projects=all_projects, bare=True, filters=filters)


@retry(openstack.exceptions.SDKException, **_retry_options)
def get_server(name_or_id):
    LOG.debug('Lookup sever by id=%r', name_or_id)
    return osc.get_server(name_or_id=name_or_id, all_projects=True)


@retry(openstack.exceptions.SDKException, **_retry_options)
def get_bound_ports(filters):
    LOG.debug('List network ports by filter: %r', filters)
    return [x for x in osc.list_ports(filters) if x.device_id]


def get_server_label_values(srv):
    """
    Get target labels from Openstack server

    Method creates map of Cloudprober target labels
    from Openstack instance parameters.

    :param srv: server object instance of class munch.Munch()

    :returns map of Cloudprober label names as keys and server
             parameters as values.
    """
    label_map = {
        "openstack": ["project_id", "hypervisor_hostname"],
        "openstack_instance": ["name", "id"],
    }
    srv_labels = {}
    for prefix, labels in label_map.items():
        for label in labels:
            srv_labels[f"{prefix}_{label}"] = getattr(srv, label)
    return srv_labels


def make_resource(server_id, address, labels):
    return {
        "ip": address,
        "name": f"{server_id}-{address}",
        "labels": dict(labels)}


def get_config_tag(main_conf, section):
    tag = None
    for target in section, main_conf:
        try:
            tag = target['tag_name']
        except KeyError:
            continue

        # unify tags interpretation
        if not tag or tag == '*':
            tag = None
        break

    return tag


def get_enabled_resource_types(config):
    result = []
    for res_type, value in config.items():
        if isinstance(value, dict) and value.get("enabled", False):
            result.append(res_type)
    return result


def make_tags_filter(tag):
    if not tag:
        return {}
    return {'tags': [tag]}


def update_targets(resources, output_file):
    """
    Update Cloudprober targets file

    Method updates targets file in case new targets
    are different from old ones.

    :param resources: List for Cloudprober resources
    :param output_file: Name of Cloudprober targets file

    :returns None
    """

    # cloudprober supports json format for targets
    hash_file = f"{output_file}.sha"

    # sort_keys=True required by the same reason as resources sorting
    payload = {'resource': sorted(resources, key=lambda x: x['name'])}
    resources_json = json.dumps(payload, sort_keys=True)
    in_sha = hashlib.sha256(resources_json.encode()).hexdigest()

    try:
        with open(hash_file, "r") as shaf:
            out_sha = shaf.read()
    except OSError:
        out_sha = ''

    if in_sha != out_sha:
        with open(output_file, "w") as outf:
            LOG.info("Updating cloudprober targets")
            outf.write(resources_json)

    # always writing hash to check its modification
    # time in liveness probe
    with open(hash_file, "w") as shaf:
        shaf.write(in_sha)


def discover_instances(main_conf, instances_conf, lookup_adapter):
    """
    Discover Openstack instances for cloudprober

    Method discovers instance interfaces and their
    ip addresses using provided criteria and updates
    cloudprober targets file.

    :param main_conf: main/global configuration settings
    :param instances_conf: Dictionary with discovery criteria and settings
    :param lookup_adapter: wrapper designed to optimise OS API calls

    :returns None
    """
    LOG.info("Starting instance discovery")
    instances_count = 0
    interface_filters = {"ext_tag": "floating"}
    output_file = instances_conf["output_file"]
    discovered = []

    tag = get_config_tag(main_conf, instances_conf)
    for srv in lookup_adapter.list_servers_by_tag(tag):
        instances_count += 1

        labels = get_server_label_values(srv)

        # discover interfaces
        instance_interfaces = meta.find_nova_interfaces(
            srv.addresses, **interface_filters
        )

        for int_spec in instance_interfaces:
            resource = make_resource(srv.id, int_spec['addr'], labels)
            resource["labels"].update(
                {"openstack_int_type": int_spec["OS-EXT-IPS:type"]})
            discovered.append(resource)
    LOG.info(
        "Instance discovery finished, instances %d, ips %d",
        instances_count, len(discovered)
    )
    update_targets(discovered, output_file)


def discover_ports(main_conf, ports_conf, lookup_adapter):
    LOG.info('Starting network ports discovery')
    discovered = []
    servers_set = set()
    ports_all = get_bound_ports(
        make_tags_filter(get_config_tag(main_conf, ports_conf)))
    for server, port, error in lookup_adapter.stream_server_port(ports_all):
        if error is not None:
            LOG.warning('Skipping %s because: %s', format_port_ref(port), error)
            continue
        if server is None:
            LOG.warning('Skipping %s because not able to map it onto the '
                        'server, device_id is empty',
                        format_port_ref(port))
            continue

        servers_set.add(server.id)
        labels = get_server_label_values(server)
        for addr in port.fixed_ips:
            resource = make_resource(server.id, addr['ip_address'], labels)
            resource["labels"]["openstack_int_type"] = 'fixed'
            discovered.append(resource)

    LOG.info(
        'Network ports discovery finished, instances %d, ports/ups %s',
        len(servers_set), len(discovered))
    update_targets(discovered, ports_conf["output_file"])


def discover_resources(lookup_adapter, resource_types, fail_on_error=False):
    """
    Discover Openstack resources for cloudprober

    :param lookup_adapter: wrapper designed to optimise OS API calls
    :param resource_types: List of names of discovered resource types

    :returns None
    """

    # Work of lookup_adapter depends from the order of resources types, some
    # resources can provide hints that will be used to optimize queries.
    # So we must force correct order of resources processing
    order = {x: idx for idx, x in enumerate(['ports'])}
    default_order = len(order)
    discovery_targets = sorted(
        resource_types,
        key=lambda subject: (order.get(subject, default_order), subject))

    try:
        for res_type in discovery_targets:
            section = config[res_type]
            if res_type == "instances":
                discover_instances(config, section, lookup_adapter)
            elif res_type == "ports":
                discover_ports(config, section, lookup_adapter)
            else:
                LOG.error('Unsupported resource type %r', res_type)
    except Exception as e:
        LOG.error(f"Discovery failed with {e}")
        if fail_on_error:
            raise e


def get_config(config_file):
    with open(config_file) as cfg:
        config = yaml.safe_load(cfg)
    # in case user set interval to 0 it will be 600
    config["interval"] = config.get("interval", 600)
    config["enabled_resource_types"] = get_enabled_resource_types(config)
    for res_type in config["enabled_resource_types"]:
        config[res_type][
            "output_file"
        ] = f"{DEFAULT_TARGETS_DIR}/openstack_{res_type}.json"
    return config


def format_port_ref(port):
    return 'port(id={}, name="{}", network_id={})'.format(
        port.id, port.name, port.network_id)


class LookupAdapter:
    def __init__(self, local_search_limit):
        self.local_search_limit = local_search_limit
        self.server_manager = ServerLookupManager()

    def reset_cache(self):
        self.server_manager = ServerLookupManager()

    def stream_server_port(self, ports):
        server_ids = {x.device_id for x in ports if x.device_id}
        server_manager = self._choose_server_manager(len(server_ids))

        for port_entry in ports:
            error = None
            try:
                server_entry = server_manager.lookup(port_entry.device_id)
            except ServerNotFoundError as e:
                server_entry = None
                error = e
            yield server_entry, port_entry, error

    def list_servers_by_tag(self, subject_tag):
        return self.server_manager.list_by_tag(subject_tag)

    def _choose_server_manager(self, expected_lookup_requests_count):
        if self.local_search_limit < expected_lookup_requests_count:
            if not isinstance(self.server_manager,
                              ServerLookupLocalSearchManager):
                LOG.debug('Switch to local server search manager')
                self.server_manager = ServerLookupLocalSearchManager()
        return self.server_manager


class ServerLookupManager:
    def __init__(self):
        self._cache = {}
        self._negative_cache = set()

    def lookup(self, name_or_id):
        if name_or_id in self._negative_cache:
            raise ServerNotFoundError(name_or_id)

        try:
            entry = self._cache[name_or_id]
        except KeyError:
            entry = get_server(name_or_id)
            if entry is None:
                self._negative_cache.add(name_or_id)
                raise ServerNotFoundError(name_or_id)
            self._cache[name_or_id] = entry
        return entry

    def list_by_tag(self, subject_tag):
        return get_servers(
            all_projects=True, filters=make_tags_filter(subject_tag))


class ServerLookupLocalSearchManager(ServerLookupManager):
    def __init__(self):
        super().__init__()
        all_servers = get_servers(all_projects=True)
        self.server_by_id = {x.id: x for x in all_servers}

    def lookup(self, name_or_id):
        try:
            entry = self.server_by_id[name_or_id]
        except KeyError:
            raise ServerNotFoundError(name_or_id)
        return entry

    def list_by_tag(self, subject_tag):
        for entry in self.server_by_id.values():
            if subject_tag and subject_tag not in entry.tags:
                continue
            yield entry


def main(lookup_adapter: LookupAdapter):
    resource_types = config["enabled_resource_types"]
    if args.daemon:
        interval = config["interval"]
        LOG.info("Starting openstack discovery service")
        while True:
            # Make discovery once script started, to avoid
            # liveness probe endless failing, when hash
            # file mtime was not updated in required period.
            discover_resources(lookup_adapter, resource_types)
            lookup_adapter.reset_cache()
            time.sleep(interval)
    else:
        discover_resources(
            lookup_adapter, resource_types, fail_on_error=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process discovery script arguments")
    parser.add_argument(
        "--daemon",
        help="Run discovery periodically and update targets file",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--config",
        help="Path to discovery configuration file",
        default=DEFAULT_CONFIG_FILE,
    )
    parser.add_argument(
        '--debug', default=False, action='store_true',
        help='Enable debug mode'
    )
    parser.add_argument(
        '--client-side-server-lookup-limit', type=int, default=16,
        dest='server_lookup_limit',
        help='If amount of server lookup operation overcomes this limit all '
             'servers list will be queried from OS compute API and lookup will '
             'be done on client side'
    )

    args = parser.parse_args()
    if args.debug:
        LOG.setLevel(logging.DEBUG)

    config = get_config(args.config)

    os_cloud = config["os_cloud"]
    osc = openstack.connect(cloud=os_cloud)

    main(LookupAdapter(args.server_lookup_limit))
