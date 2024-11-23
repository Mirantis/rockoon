#    Copyright 2020 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import asyncio
import socket

from datetime import datetime
from enum import IntEnum

from keystoneauth1 import exceptions as ksa_exceptions
import kopf
import openstack
import os_service_types

from rockoon import settings
from rockoon import utils
from rockoon import maintenance

LOG = utils.get_logger(__name__)

ADMIN_CREDS = None


class SERVER_POWER_STATES(IntEnum):
    NOSTATE = 0
    RUNNING = 1
    PAUSED = 3
    SHUTDOWN = 4
    CRASHED = 6
    SUSPENDED = 7


# States save to host reboot.
SERVER_STOPPED_POWER_STATES = [
    SERVER_POWER_STATES.SHUTDOWN,
    SERVER_POWER_STATES.CRASHED,
    SERVER_POWER_STATES.SUSPENDED,
]


# NOTE(vsaienko): skip pausing on instances in following states, as they are not running.
# Avoid adding error here, as in this state instance might be running state.
SERVER_STATES_SAFE_FOR_REBOOT = [
    "building",
    "deleted",
    "soft_deleted",
    "stopped",
    "suspended",
    "shelved",
    "shelve_offloaded",
]


COMPUTE_SERVICE_DISABLE_REASON = "OSDPL: Node is under maintenance"
VOLUME_SERVICE_DISABLED_REASON = COMPUTE_SERVICE_DISABLE_REASON


class OpenStackClientManager:
    def __init__(self, cloud=settings.OS_CLOUD, metrics=None):
        # NOTE(vsaienko): disable built in opestacksdk metrics as they
        # leads to deadlock in custom collectors.
        # https://github.com/prometheus/client_python/issues/353
        if metrics is None:
            metrics = {"prometheus": {"enabled": False}}
        self.oc = openstack.connect(
            cloud=cloud, metrics=metrics, api_timeout=300
        )
        self.service_type_manager = os_service_types.ServiceTypes()

    def volume_get_services(self, **kwargs):
        res = []
        params = {k: v for k, v in kwargs.items() if v is not None}
        resp = self.oc.block_storage.get("/os-services", params=params)
        if resp.ok:
            res = resp.json()["services"]
        return res

    def volume_get_volumes(self, host=None, all_tenants=True):
        def match_host(volume, host=None):
            if host is None:
                return True
            volume_host = volume.get("host")
            if volume_host is None:
                return
            return host == volume_host.split("@")[0]

        return [
            x
            for x in self.oc.block_storage.volumes(all_tenants=all_tenants)
            if match_host(x, host)
        ]

    def volume_ensure_service_disabled(
        self, host, binary="cinder-volume", disabled_reason=None
    ):
        data = {"binary": binary, "host": host}
        if disabled_reason is not None:
            data["disabled_reason"] = disabled_reason
        self.oc.block_storage.put("/os-services/disable-log-reason", json=data)

    def volume_ensure_service_enabled(self, host, binary="cinder-volume"):
        data = {"binary": binary, "host": host}
        self.oc.block_storage.put("/os-services/enable", json=data)

    def compute_get_services(self, host=None, binary="nova-compute"):
        return list(self.oc.compute.services(host=host, binary=binary))

    def compute_ensure_service_enabled(self, service):
        if service["status"].lower() != "enabled":
            self.oc.compute.update_service(service["id"], status="enabled")

    def compute_ensure_service_disabled(self, service, disabled_reason=None):
        if service["status"].lower() != "disabled":
            self.oc.compute.update_service(
                service["id"],
                status="disabled",
                disabled_reason=disabled_reason,
            )

    def compute_ensure_service_force_down(self, service, forced_down):
        state = "down" if forced_down else "up"
        if service["state"].lower() != state:
            self.oc.compute.update_service(
                service["id"],
                forced_down=forced_down,
            )

    def compute_ensure_services_absent(self, host):
        for service in self.compute_get_services(host=host, binary=None):
            self.oc.compute.delete_service(service)

    async def compute_wait_service_state(
        self, host, binary=None, state="down"
    ):
        alive = [False]
        while not all(alive):
            alive = [
                service["state"] == state
                for service in self.compute_get_services(
                    host=host, binary=binary
                )
            ]
            LOG.info(f"Waiting 30 for compute services are down on the {host}")
            await asyncio.sleep(30)

    def compute_get_all_servers(self, host=None, status=None):
        filters = {}
        if host:
            filters["host"] = host
        if status:
            filters["status"] = status
        return self.oc.list_servers(
            detailed=False, all_projects=True, filters=filters
        )

    def compute_get_servers_valid_for_live_migration(self, host=None):
        servers = []
        for status in ["ACTIVE", "PAUSED"]:
            servers.extend(
                list(self.compute_get_all_servers(host=host, status=status))
            )
        servers = [s for s in servers if s.task_state != "migrating"]
        return servers

    def compute_get_servers_in_migrating_state(self, host=None):
        return self.compute_get_all_servers(host=host, status="MIGRATING")

    def compute_get_availability_zones(self, details=False):
        return list(self.oc.compute.availability_zones(details=details))

    def baremetal_get_nodes(self):
        return self.oc.baremetal.nodes()

    def baremetal_is_node_available(self, node):
        """Check if node is available for provisioning

        The node is threated as available for provisioning when:
        1. maintenance flag is Flase
        2. No instance_uuid is assigned
        3. The provision_state is available

        """

        return all(
            # TODO(vsaienko) use maintenance, instance_uuid
            # when switch to osclient of zed version.
            [
                node["is_maintenance"] is False,
                node["instance_id"] is None,
                node["provision_state"] == "available",
            ]
        )

    def instance_ha_create_notification(
        self, type, hostname, payload, generated_time=None
    ):
        if not generated_time:
            generated_time = datetime.utcnow().isoformat(timespec="seconds")
        return self.oc.instance_ha.create_notification(
            type=type,
            hostname=hostname,
            generated_time=generated_time,
            payload=payload,
        )

    def network_get_agents(
        self,
        host=None,
        is_alive=None,
        is_admin_state_up=None,
        binary=None,
        agent_type=None,
    ):
        kwargs = {}
        if host is not None:
            kwargs["host"] = host
        if is_alive is not None:
            kwargs["is_alive"] = is_alive
        if is_admin_state_up is not None:
            kwargs["is_admin_state_up"] = is_admin_state_up
        if binary is not None:
            kwargs["binary"] = binary
        if agent_type is not None:
            kwargs["agent_type"] = agent_type
        try:
            yield from self.oc.network.agents(**kwargs)
        except openstack.exceptions.ResourceNotFound:
            pass
        return []

    def network_ensure_agent_enabled(self, agent):
        if agent["is_admin_state_up"] is False:
            self.oc.network.update_agent(agent, admin_state_up=True)

    def network_ensure_agent_disabled(self, agent):
        if agent["is_admin_state_up"] is True:
            self.oc.network.update_agent(agent, admin_state_up=False)

    def network_ensure_agents_absent(self, host):
        for agent in self.network_get_agents(host=host):
            self.oc.network.delete_agent(agent)

    async def network_wait_agent_state(self, host, is_alive=True):
        alive = [False]
        while not all(alive):
            alive = [
                service["is_alive"] == is_alive
                for service in self.network_get_agents(host=host)
            ]
            LOG.info(f"Waiting 30 for network agents are down on the {host}")
            await asyncio.sleep(30)

    def network_get_availability_zones(self):
        try:
            yield from self.oc.network.availability_zones()
        except openstack.exceptions.ResourceNotFound:
            pass
        return []

    def network_get_ports(self, device_owner=None):
        kwargs = {}
        if device_owner is not None:
            kwargs["device_owner"] = device_owner
        try:
            yield from self.oc.network.ports(**kwargs)
        except openstack.exceptions.ResourceNotFound:
            pass
        return []

    def network_ensure_ports_absent(self, device_owner):
        for port in self.network_get_ports(device_owner=device_owner):
            self.oc.network.delete_port(port)

    def placement_resource_provider_absent(self, host):
        rp_list = list(self.oc.placement.resource_providers())
        for rp in rp_list:
            if rp["name"].split(".")[0] == host:
                self.oc.placement.delete_resource_provider(rp)

    def network_floating_ip_update(self, fip_id, data):
        return self.oc.network.put(
            f"/floatingips/{fip_id}/", json={"floatingip": data}
        ).json()


def notify_masakari_host_down(node):
    try:
        os_client = OpenStackClientManager()
        notification = os_client.instance_ha_create_notification(
            type="COMPUTE_HOST",
            hostname=node.name,
            generated_time=datetime.utcnow().isoformat(timespec="seconds"),
            payload={"event": "STOPPED", "host_status": "NORMAL"},
        )
        LOG.info(f"Sent notification {notification} to Masakari API")
    except ksa_exceptions.EndpointNotFound:
        LOG.info("Instance-HA service is not deployed, ignore notifying")
        return
    except Exception as e:
        if isinstance(e, openstack.exceptions.HttpException):
            # NOTE(vsaienko): do not resend notifications if host does not belong
            # to any segments.
            if e.status_code in [400, 409]:
                LOG.warning(e)
                return
        LOG.warning(f"Failed to notify Masakari - {e}")
        raise kopf.TemporaryError(f"{e}") from e


def handle_masakari_host_down(node):
    """Handle down host for masakari.

    :param node: Kubernetes node object to check.
    :raises TemporaryError: When restart of handler is needed. We are not sure
            and need to recheck later.
    """
    node.reload()
    if node.ready:
        LOG.info(f"The node {node.name} is ready. Skip masakari notification")
        return
    nwl = maintenance.NodeWorkloadLock.get_by_node(node.name)
    # NOTE(pas-ha): guard against node being in maintenance
    # when node is already being drained
    # we assume that at this stage the workflow with NodeWorkloadLocks
    # and auto-migration of workloads is happening instead of using Masakari
    if not nwl.is_active():
        LOG.info(
            f"The nwl for node {node.name} is inctive. Skip masakari notification."
        )
        return
    if node.unschedulable:
        LOG.info(
            f"The scheduling is disabled on node {node.name}, this is intentional, skip masakari notification."
        )
        return
    try:
        os_client = OpenStackClientManager()
        if len(os_client.compute_get_all_servers(host=node.name)) == 0:
            LOG.info(
                f"Do not have servers on the host {node.name}, skip masakari notification."
            )
            return
        compute_services = os_client.compute_get_services(host=node.name)
        alive_services = [
            service["state"] == "up" for service in compute_services
        ]
        if any(alive_services):
            raise kopf.TemporaryError(
                f"Some compute services {compute_services} are still alive. Skip masakari notification, will check later."
            )
        alive_network_agents = os_client.network_get_agents(
            host=node.name, is_alive=True
        )

        if any(alive_network_agents):
            raise kopf.TemporaryError(
                f"Some network agents are alive {alive_network_agents}. Skip masakari notification, will check later."
            )

        node_internal_ip = []
        for address in node.obj["status"].get("addresses", []):
            if address.get("type") == "InternalIP" and "address" in address:
                node_internal_ip = address["address"]
                break
        if node_internal_ip:
            sock = socket.socket()
            sock.settimeout(10)
            try:
                sock.connect((node_internal_ip, 22))
            except Exception:
                LOG.info(
                    f"Port 22 is not opened on host {node.name} {node_internal_ip}. We should notify masakari that host is down."
                )
                notify_masakari_host_down(node)
                return
            finally:
                sock.close()
            raise kopf.TemporaryError(
                f"Port 22 is opened on host {node.name}. Skip masakari notification, will check later."
            )
    except ksa_exceptions.EndpointNotFound:
        LOG.info("Instance-HA service is not deployed, ignore notifying")
    except Exception as e:
        LOG.warning(f"Failed to handle host down for Masakari - {e}")
        raise kopf.TemporaryError(f"{e}") from e
