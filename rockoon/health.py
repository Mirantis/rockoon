import asyncio
import logging

import kopf

from rockoon.services import base
from rockoon import constants
from rockoon import settings
from rockoon import layers

LOG = logging.getLogger(__name__)
CONF = settings.CONF


def ident(meta):
    name = meta["name"]
    application = meta.get("labels", {}).get("application", name)
    component = meta.get("labels", {}).get("component", name)

    # single out prometheus-exported Deployments
    if application.startswith("prometheus") and component == "exporter":
        application = "prometheus-exporter"
        # examples:
        # name=openstack-barbican-rabbitmq-rabbitmq-exporter
        # name=openstack-memcached-memcached-exporter
        # name=prometheus-mysql-exporter
        prefix, component, *parts = name.split("-")
        if parts[0] == "rabbitmq" and component != "rabbitmq":
            component += "-rabbitmq"
    # single out rabbitmq StatefulSets
    # examples:
    # name=openstack-nova-rabbitmq-rabbitmq
    # name=openstack-rabbitmq-rabbitmq
    elif application == "rabbitmq" and component == "server":
        prefix, service, *parts = name.split("-")
        if service != "rabbitmq":
            application = service
            component = "rabbitmq"
    else:
        # For other cases pick component name from resource name to allow multiple
        # resources per same component/application.
        # Remove redundant {applicaion}- part
        short_component_name = name.split(f"{application}-", maxsplit=1)[-1]
        if short_component_name:
            component = short_component_name

    return application, component


def set_multi_application_health(osdplst, patch):
    LOG.debug(f"Set multi application health")
    osdplst.set_osdpl_health(patch)


def is_application_ready(application, osdplst):
    osdplst.reload()

    app_status = (
        osdplst.obj.get("status", {}).get("health", {}).get(application)
    )
    if not app_status:
        LOG.info(
            f"Application: {application} is not present in .status.health."
        )
        return False
    elif all(
        [
            component_health["status"] == constants.K8sObjHealth.OK.value
            for component_health in app_status.values()
        ]
    ):
        LOG.info(f"All components for application: {application} are healthy.")
        return True

    not_ready = [
        component
        for component, health in app_status.items()
        if health["status"] != "Ready"
    ]
    LOG.info(
        f"Some components for application: {application} not ready: {not_ready}"
    )
    return False


async def _wait_application_ready(application, osdplst, delay=None):
    delay = delay or CONF.getint("osctl", "wait_application_ready_delay")
    i = 1
    while not is_application_ready(application, osdplst):
        LOG.info(f"Checking application {application} health, attempt: {i}")
        i += 1
        await asyncio.sleep(delay)


async def wait_application_ready(
    application,
    osdplst,
    timeout=None,
    delay=None,
):
    timeout = timeout or CONF.getint("osctl", "wait_application_ready_timeout")
    delay = delay or CONF.getint("osctl", "wait_application_ready_delay")
    LOG.info(f"Waiting for application becomes ready for {timeout}s")
    await asyncio.wait_for(
        _wait_application_ready(application, osdplst, delay=delay),
        timeout=timeout,
    )


async def wait_services_healthy(mspec, osdplst, child_view):
    """Wait all openstack related services are healthy."""

    services = [
        base.Service.registry[i](mspec, LOG, osdplst, child_view)
        for i in layers.services(mspec, LOG)[0]
    ]
    for service in services:
        try:
            await service.wait_service_healthy()
        except Exception as e:
            LOG.info(
                f"Time out waiting health for service {service.service}. Error: {e}",
            )
            raise kopf.TemporaryError("Services are not healthy")
    return True


def health_status(obj):
    res = constants.K8sObjHealth.BAD.value
    if obj.ready:
        res = constants.K8sObjHealth.OK.value
    return res
