import asyncio

import kopf

from rockoon import kube
from rockoon import health
from rockoon import settings
from rockoon import utils
from rockoon import services
from rockoon import maintenance
from rockoon import osdplstatus
from rockoon import resource_view


LOG = utils.get_logger(__name__)


def maintenance_node_name(body):
    return body["spec"]["nodeName"].split(".")[0]


@kopf.on.create(*maintenance.NodeMaintenanceRequest.kopf_on_args)
@kopf.on.update(*maintenance.NodeMaintenanceRequest.kopf_on_args)
@kopf.on.resume(*maintenance.NodeMaintenanceRequest.kopf_on_args)
def node_maintenance_request_change_handler(body, **kwargs):
    asyncio.run(_node_maintenance_request_change_handler(body, **kwargs))


async def _node_maintenance_request_change_handler(body, **kwargs):
    name = body["metadata"]["name"]
    node_name = maintenance_node_name(body)
    LOG.info(f"Got node maintenance request change event {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    node = kube.safe_get_node(node_name)
    if not node.exists():
        return
    nwl = maintenance.NodeWorkloadLock.get_by_node(node_name)
    nmr = maintenance.NodeMaintenanceRequest.get_resource(body)
    if not nwl.required_for_node(node_name):
        return

    nwl.present()

    # NOTE(vsaienko): check if current node is in maintenance to let
    # retry on Exception here.
    nwl.acquire_internal_lock()

    osdpl = kube.get_osdpl()
    if not osdpl or not osdpl.exists():
        LOG.info("Can't find OpenStackDeployment object")
        nwl.set_state_inactive()
        nwl.unset_error_message()
        return

    mspec = osdpl.mspec
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    child_view = resource_view.ChildObjectView(mspec)

    if nwl.is_active():
        # Verify if we can handle nmr by specific services.
        active_locks = nwl.maintenance_locks()
        services_can_handle_nmr = {}
        for service_name, service_class in services.ORDERED_SERVICES:
            service = service_class(mspec, LOG, osdplst, child_view)
            if service.maintenance_api:
                services_can_handle_nmr[service_name] = (
                    await service.can_handle_nmr(node, active_locks)
                )
        if not all(services_can_handle_nmr.values()):
            msg = f"Some services blocks nmr handling {services_can_handle_nmr}. Deferring processing for node {node.name}"
            nwl.set_error_message(msg)
            raise kopf.TemporaryError(msg)

        nwl.set_inner_state_active()
        for service, service_class in services.ORDERED_SERVICES:
            service = service_class(mspec, LOG, osdplst, child_view)
            if service.maintenance_api:
                LOG.info(
                    f"Got moving node {node_name} into maintenance for {service_class.service}"
                )
                await service.process_nmr(node, nmr)
                LOG.info(
                    f"The node {node_name} is ready for maintenance for {service_class.service}"
                )
    nwl.set_state_inactive()
    nwl.unset_error_message()
    LOG.info(f"Released NodeWorkloadLock for node {node_name}")


@kopf.on.delete(*maintenance.NodeMaintenanceRequest.kopf_on_args)
def node_maintenance_request_delete_handler(body, **kwargs):
    asyncio.run(_node_maintenance_request_delete_handler(body, **kwargs))


async def _node_maintenance_request_delete_handler(body, **kwargs):
    name = body["metadata"]["name"]
    node_name = maintenance_node_name(body)
    LOG.info(f"Got node maintenance request delete event {name}")

    node = kube.safe_get_node(node_name)
    nwl = maintenance.NodeWorkloadLock.get_by_node(node_name)
    if node.exists():
        nmr = maintenance.NodeMaintenanceRequest.get_resource(body)
        if not nwl.required_for_node(node_name):
            LOG.info(
                f"Removing nodeworkloadlock for node {node_name} as its not required."
            )
            nwl.absent(propagation_policy="Background")
            return

        osdpl = kube.get_osdpl()
        if not osdpl or not osdpl.exists():
            LOG.info("Can't find OpenStackDeployment object")
            nwl.set_inner_state_inactive()
            nwl.set_state_active()
            nwl.unset_error_message()
            return

        if nwl.is_maintenance():
            LOG.info(f"Waiting for {node.name} is ready.")
            while True:
                if not node.ready:
                    LOG.info(f"The node {node.name} is not ready yet.")
                    await asyncio.sleep(10)
                    continue
                LOG.info(f"The node {node.name} is ready.")
                break

            while True:
                LOG.info(f"Waiting for pods ready on node {node.name}.")
                node_pods = node.get_pods(namespace=osdpl.namespace)
                not_ready_pods = [
                    pod.name
                    for pod in node_pods
                    if not pod.job_child and not pod.ready
                ]
                if not_ready_pods:
                    LOG.info(f"The pods {not_ready_pods} are not ready.")
                    await asyncio.sleep(10)
                    continue
                LOG.info(f"All pods are ready on node {node.name}.")
                break

            mspec = osdpl.mspec
            osdplst = osdplstatus.OpenStackDeploymentStatus(
                osdpl.name, osdpl.namespace
            )
            child_view = resource_view.ChildObjectView(mspec)

            for service, service_class in reversed(services.ORDERED_SERVICES):
                service = service_class(mspec, LOG, osdplst, child_view)
                if service.maintenance_api:
                    LOG.info(
                        f"Moving node {node_name} to operational state for {service_class.service}"
                    )
                    await service.delete_nmr(node, nmr)
                    LOG.info(
                        f"The node {node_name} is ready for operations for {service_class.service}"
                    )
    nwl.set_inner_state_inactive()
    nwl.set_state_active()
    nwl.unset_error_message()
    LOG.info(f"Acquired NodeWorkloadLock for node {node_name}")


@kopf.on.create(*maintenance.ClusterMaintenanceRequest.kopf_on_args)
@kopf.on.update(*maintenance.ClusterMaintenanceRequest.kopf_on_args)
@kopf.on.resume(*maintenance.ClusterMaintenanceRequest.kopf_on_args)
def cluster_maintenance_request_change_handler(body, **kwargs):
    name = body["metadata"]["name"]
    LOG.info(f"Got cluster maintenance request change event {name}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    osdpl = kube.get_osdpl()
    if not osdpl or not osdpl.exists():
        LOG.info("Can't find OpenStackDeployment object")
        return

    mspec = osdpl.mspec
    osdpl_name = osdpl.metadata["name"]
    osdpl_namespace = osdpl.metadata["namespace"]
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl_name, osdpl_namespace
    )
    osdplst_status = osdplst.get_osdpl_status()
    child_view = resource_view.ChildObjectView(mspec)
    cwl = maintenance.ClusterWorkloadLock.get_by_osdpl(osdpl_name)

    # Do not handle CMR while CWL release string contains old release.
    if cwl.get_release() != settings.OSCTL_CLUSTER_RELEASE:
        msg = (
            f"Waitinging for cwl release is {settings.OSCTL_CLUSTER_RELEASE}."
        )
        cwl.set_error_message(msg)
        raise kopf.TemporaryError(msg)

    if osdplst_status != osdplstatus.APPLIED:
        msg = (
            f"Waiting osdpl status APPLIED, current state is {osdplst_status}"
        )
        cwl.set_error_message(msg)
        raise kopf.TemporaryError(msg)

    if not cwl.is_active():
        # NOTE(vsaienko): we are in maintenance, but controller is restarted, do
        # not wait for health
        return
    cwl.set_error_message("Waiting for all OpenStack services are healthy.")
    asyncio.run(health.wait_services_healthy(mspec, osdplst, child_view))

    cwl.set_state_inactive()
    cwl.unset_error_message()
    LOG.info(f"Released {name} ClusterWorkloadLock")


@kopf.on.delete(*maintenance.ClusterMaintenanceRequest.kopf_on_args)
def cluster_maintenance_request_delete_handler(body, **kwargs):
    name = body["metadata"]["name"]
    LOG.info(f"Got cluster maintenance request delete event {name}")

    osdpl = kube.get_osdpl()
    if not osdpl or not osdpl.exists():
        LOG.info("Can't find OpenStackDeployment object")
        return
    name = osdpl.metadata["name"]
    cwl = maintenance.ClusterWorkloadLock.get_by_osdpl(name)
    cwl.set_state_active()
    cwl.unset_error_message()
    LOG.info(f"Acquired ClusterWorkloadLock {name}")


@kopf.on.create(*maintenance.NodeDeletionRequest.kopf_on_args)
@kopf.on.update(*maintenance.NodeDeletionRequest.kopf_on_args)
@kopf.on.resume(*maintenance.NodeDeletionRequest.kopf_on_args)
def node_deletion_request_change_handler(body, **kwargs):
    asyncio.run(_node_deletion_request_change_handler(body, **kwargs))


async def _node_deletion_request_change_handler(body, **kwargs):
    name = body["metadata"]["name"]
    node_name = maintenance_node_name(body)
    LOG.info(f"Got node deletion request change event {name}")

    osdpl = kube.get_osdpl()
    nwl = maintenance.NodeWorkloadLock.get_by_node(node_name)
    if osdpl and osdpl.exists():
        mspec = osdpl.mspec
        osdpl_name = osdpl.metadata["name"]
        osdpl_namespace = osdpl.metadata["namespace"]
        osdplst = osdplstatus.OpenStackDeploymentStatus(
            osdpl_name, osdpl_namespace
        )
        child_view = resource_view.ChildObjectView(mspec)
        node = kube.safe_get_node(node_name)
        if node.exists():
            for service, service_class in reversed(services.ORDERED_SERVICES):
                service = service_class(mspec, LOG, osdplst, child_view)
                if service.maintenance_api:
                    LOG.info(
                        f"Handling node deletion for {node_name} by service {service_class.service}"
                    )
                    await service.process_ndr(node, nwl)
                    LOG.info(
                        f"The node {node_name} is ready for deletion by {service_class.service}"
                    )

    nwl.set_state_inactive()
    nwl.unset_error_message()
    LOG.info(f"The node {node_name} is ready for deletion.")


@kopf.on.delete(*maintenance.NodeWorkloadLock.kopf_on_args)
def node_workloadlock_request_delete_handler(body, **kwargs):
    asyncio.run(_node_workloadlock_request_delete_handler(body, **kwargs))


async def _node_workloadlock_request_delete_handler(body, **kwargs):
    name = body["metadata"]["name"]
    node_name = body["spec"]["nodeName"]
    LOG.info(f"Got nodeworkloadlock deletion request change event {name}")

    if not body["spec"].get("controllerName") == "openstack":
        return

    osdpl = kube.get_osdpl()
    if not (osdpl and osdpl.exists()):
        return

    # NOTE(vsaienko): later we do destructive calls like
    # openstack metadata removal and persistent data removal (database PVC removal)
    # it is important to ensure node is removed to double confirm that we are
    # doing what was requested.
    # It is important to cleanup metadata when node is reamoved and services are
    # not running anymore, otherwise they will add itself into the service tables.
    node = kube.safe_get_node(name)
    if node.exists():
        msg = "The kubernetes node {node_name} still exists. Deffer OpenStack service metadata removal."
        raise kopf.TemporaryError(msg)

    nwl = maintenance.NodeWorkloadLock.get_by_node(node_name)
    mspec = osdpl.mspec
    osdpl_name = osdpl.metadata["name"]
    osdpl_namespace = osdpl.metadata["namespace"]
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl_name, osdpl_namespace
    )
    child_view = resource_view.ChildObjectView(mspec)

    for service, service_class in reversed(services.ORDERED_SERVICES):
        service = service_class(mspec, LOG, osdplst, child_view)
        if service.maintenance_api:
            LOG.info(f"Cleaning metadata for {service.service} on node {name}")
            await service.cleanup_metadata(nwl)
            LOG.info(
                f"Cleaning persistant data for {service.service} on node {name}"
            )
            await service.cleanup_persistent_data(nwl)

    LOG.info(
        f"The nodeworkloadlock for node {node_name} is ready for deletion."
    )


@kopf.on.delete(*maintenance.NodeDisableNotification.kopf_on_args)
def node_disable_notification_delete_handler(body, **kwargs):
    name = body["metadata"]["name"]
    node_name = body["spec"]["nodeName"]
    LOG.info(
        f"Got nodedisablenotifications deletion request change event {name}"
    )

    node = kube.safe_get_node(node_name)
    if not node.exists():
        nwl = maintenance.NodeWorkloadLock.get_by_node(node_name)
        LOG.info(
            f"Removing nodeworkloadlock for node {node_name} as node was disabled and was just removed."
        )
        nwl.absent(propagation_policy="Background")
    LOG.info(f"Finished handling nodedisablenotifications for {node_name}.")
