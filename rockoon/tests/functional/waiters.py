import os
import time
import logging
from datetime import datetime
import openstack

from rockoon.tests.functional import config

LOG = logging.getLogger(__name__)
CONF = config.Config()


def wait_for_job_status(job, status, timeout, interval):
    """
    :param status: string "ready" or "completed"
    """
    start_time = int(time.time())
    while True:
        if getattr(job, status):
            LOG.debug(
                f"Job is {status}. Current job status is {job.obj['status']}."
            )
            return
        time.sleep(interval)
        timed_out = int(time.time()) - start_time
        message = f"Job is not {status} after {timed_out} sec."
        if timed_out >= timeout:
            LOG.error(message)
            raise TimeoutError(message)


def wait_for_service_status_state(
    fetch_function, svc, expected_status, timeout, interval
):
    start_time = int(time.time())
    while True:
        current_service_status = fetch_function(svc)
        if current_service_status == expected_status:
            LOG.debug(f"Current service status is {current_service_status}.")
            return
        time.sleep(interval)
        timed_out = int(time.time()) - start_time
        message = (
            f"Service status or state hasn't changed after {timed_out} sec."
        )
        if timed_out >= timeout:
            LOG.error(message)
            raise TimeoutError(message)


def wait_for_server_status(openstack_client, server, status):
    start_time = int(time.time())
    timeout = CONF.SERVER_TIMEOUT
    while True:
        server = openstack_client.oc.get_server(server.id)
        if server.status.upper() == status.upper():
            LOG.debug(f"Server {server.id} has status: {server.status}.")
            return
        time.sleep(CONF.SERVER_READY_INTERVAL)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            message = (
                f"Server {server.id} failed to reach {status} "
                f"status within the required time {timeout}"
            )
            LOG.error(message)
            raise TimeoutError(message)


def wait_for_port_status(openstack_client, port, status):
    start_time = int(time.time())
    timeout = CONF.SERVER_TIMEOUT
    while True:
        port = openstack_client.oc.network.get_port(port.id)
        if port.status.upper() == status.upper():
            LOG.debug(f"Port {port.id} has status: {port.status}.")
            return
        time.sleep(CONF.SERVER_READY_INTERVAL)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            message = (
                f"Port {port.id} failed to reach {status} "
                f"status within the required time {timeout}"
            )
            LOG.error(message)
            raise TimeoutError(message)


def wait_for_network_portprober_ports(
    openstack_client, network_id, port_number
):
    start_time = int(time.time())
    timeout = CONF.PORTPROBER_METRIC_TIMEOUT
    while True:
        ports = list(
            openstack_client.oc.network.ports(
                network_id=network_id, device_owner="network:portprober"
            )
        )
        if len(ports) == port_number:
            return
        time.sleep(10)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            message = (
                f"Timeoud out waiting network:portprober ports {port_number} "
                f"for network {network_id} within the required time {timeout}"
            )
            LOG.error(message)
            raise TimeoutError(message)


def wait_resource_field(
    get_resource_func, resource_id, fields, timeout, interval
):
    start_time = time.time()
    while True:
        resource = get_resource_func(resource_id)
        for field, field_value in fields.items():
            if resource.get(field) != field_value:
                time.sleep(interval)
                break
        else:
            return
        if time.time() - start_time >= timeout:
            message = f"Timed out while waiting required fields '{field}' on resource {resource}"
            LOG.error(message)
            raise TimeoutError(message)


def wait_resource_deleted(
    get_resource_func,
    resource_id,
    timeout,
    interval,
    deleted_key=None,
    deleted_value="DELETED",
):
    start_time = int(time.time())
    while int(time.time()) - start_time < timeout:
        try:
            responce = get_resource_func(resource_id)
        except openstack.exceptions.ResourceNotFound:
            return
        if (responce is None) or (
            deleted_key and responce.get(deleted_key) == deleted_value
        ):
            return
        time.sleep(interval)

    message = f"Timed out while waiting for resource {resource_id} is deleted"
    LOG.error(message)
    raise TimeoutError(message)


def wait_cinder_pool_updated(
    get_cinder_pool_timestamp, pool_name, timestamp=None
):
    last_timestamp = timestamp or get_cinder_pool_timestamp(pool_name)
    start_time = time.time()
    timeout = CONF.CINDER_POOL_UPDATE_TIMEOUT
    while True:
        timestamp = get_cinder_pool_timestamp(pool_name)
        if timestamp > last_timestamp:
            LOG.debug(f"Cinder pool {pool_name} has updated")
            return
        time.sleep(CONF.CINDER_POOL_UPDATE_INTERVAL)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            message = (
                f"Pool {pool_name} hasn't updated within {timeout} seconds"
            )
            LOG.error(message)
            raise TimeoutError(message)


def wait_for_ping(ip, timeout=60, interval=5):
    start = int(time.time())
    while int(time.time()) - start < timeout:
        res = os.system(f"ping -c1 -w1 {ip}")
        if res == 0:
            return
        time.sleep(interval)
    raise TimeoutError(
        "Timed out waiting ping reply in {timeout} seconds from {ip}"
    )


def wait_for_instance_migration(openstack_client, server):
    start_time = time.time()
    timeout = CONF.SERVER_LIVE_MIGRATION_TIMEOUT
    initial_server_host = openstack_client.oc.get_server(
        server.id
    ).compute_host
    while True:
        server = openstack_client.oc.get_server(server.id)
        if (
            server.compute_host != initial_server_host
            and server.status == "ACTIVE"
        ):
            LOG.debug(
                f"Server {server.id} has migrated during dynamic resource rebalancing"
            )
            return
        time.sleep(60)
        timed_out = int(time.time()) - start_time
        if timed_out >= timeout:
            message = (
                f"Server {server.id} hasn't migrated "
                f"during dynamic resource rebalancing "
                f"within the required time {timeout}"
            )
            LOG.error(message)
            raise TimeoutError(message)


def wait_nwl_state(nwl, state):
    start_time = time.time()
    timeout = CONF.NWL_STATE_TIMEOUT

    while int(time.time()) - start_time <= timeout:
        nwl.reload()
        if nwl.obj["status"].get("state", "active") == state:
            return
        time.sleep(10)
    raise TimeoutError(
        f"Timed out waiting nwl {nwl.name} to be in {state} after {timeout}."
    )


def wait_k8s_obj_absent(obj):
    start_time = time.time()
    timeout = CONF.NWL_STATE_TIMEOUT

    while int(time.time()) - start_time <= timeout:
        if not obj or not obj.exists():
            return
        time.sleep(10)
    raise TimeoutError(
        f"Timed out waiting k8s obj {obj.kind}/{obj.name} is absent after {timeout}."
    )


def wait_compute_is_empty(oc, host, timeout=60):
    start_time = time.time()
    timeout = CONF.NWL_STATE_TIMEOUT
    while int(time.time()) - start_time <= timeout:
        if (
            len(
                list(
                    oc.compute.servers(
                        all_projects=True, filters={"compute_host": host}
                    )
                )
            )
            == 0
        ):
            return
        time.sleep(10)
    raise TimeoutError(
        f"Timeoud out waiting for hypervisor {host} is empty after {timeout}."
    )


def wait_compute_service_state(
    oc, host, state, status, binary="nova-compute", timeout=60
):
    start_time = time.time()
    timeout = CONF.NWL_STATE_TIMEOUT
    services = []
    while int(time.time()) - start_time <= timeout:
        services = list(oc.compute.services(host=host, binary=binary))
        expected = [
            x["state"] == state and x["status"] == status for x in services
        ]
        if expected and all(expected):
            return
        time.sleep(10)
    raise TimeoutError(
        f"Timeoud out waiting for compute {binary} service on {host} is in state: {state}/status: {status} after {timeout}. Last services: {services}"
    )


def wait_masakari_notification(
    fetch_function,
    server_uuid,
    start_timestamp,
    notification_type,
    status="finished",
    event="LIFECYCLE",
    timeout=CONF.MASAKARI_NOTIFICATION_TIMEOUT,
):
    start_time = int(time.time())
    while int(time.time()) - start_time <= timeout:
        notifications = fetch_function()

        relevant_notifications = []
        for notification in notifications:
            created_time = notification.get("created_at")
            notification_timestamp = int(
                datetime.strptime(
                    created_time, "%Y-%m-%dT%H:%M:%S.%f"
                ).timestamp()
            )
            if notification_timestamp > start_timestamp:
                relevant_notifications.append(notification)

        for notification in relevant_notifications:
            if (
                notification["payload"]["instance_uuid"] == server_uuid
                and notification["type"] == notification_type
                and notification["status"] == status
                and notification["payload"]["event"] == event
            ):
                return True
        time.sleep(30)
        timed_out = int(time.time()) - start_time
        message = f"Number of Masakari notifications didn't change during {timeout} sec"
        if timed_out >= timeout:
            LOG.error(message)
            raise TimeoutError(message)
