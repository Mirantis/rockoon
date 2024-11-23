import asyncio
import kopf

from rockoon import batch_health
from rockoon import constants
from rockoon import health
from rockoon import hooks
from rockoon import kube
from rockoon import settings  # noqa
from rockoon import utils
from rockoon import osdplstatus


LOG = utils.get_logger(__name__)
CONF = settings.CONF

# DAEMONSET_HOOKS format
# {(transition state from, transition state to):
#    {application-component: func to be called}}
# node added in two transitions:
# 1. from Ready to Unhealthy
# 2. Unhealthy to Ready
# node removed in two transitions:
# 1. from Ready to Progressing
# 2. from Progressing to Ready
DAEMONSET_HOOKS = {
    (constants.K8sObjHealth.BAD.value, constants.K8sObjHealth.OK.value): {
        "nova-compute-default": hooks.run_nova_cell_setup
    },
    (constants.K8sObjHealth.OK.value, constants.K8sObjHealth.BAD.value): {
        "octavia-health-manager-default": hooks.run_octavia_create_resources
    },
}


@kopf.on.delete("apps", "v1", "deployments")
def deployments(name, namespace, meta, status, new, reason, **kwargs):
    LOG.debug(f"Deployment {name} status.conditions is {status}")
    osdpl = kube.get_osdpl(namespace)
    if not osdpl:
        return
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    application, component = health.ident(meta)
    osdplst.remove_osdpl_service_health(application, component)


@kopf.on.delete("apps", "v1", "statefulsets")
def statefulsets(name, namespace, meta, status, reason, **kwargs):
    LOG.debug(f"StatefulSet {name} status is {status}")
    osdpl = kube.get_osdpl(namespace)
    if not osdpl:
        return
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    application, component = health.ident(meta)
    osdplst.remove_osdpl_service_health(application, component)


@kopf.on.field("apps", "v1", "daemonsets", field="status")
@kopf.on.delete("apps", "v1", "daemonsets")
def daemonsets(name, namespace, meta, status, reason, **kwargs):
    LOG.debug(f"DaemonSet {name} status is {status}")
    osdpl = kube.get_osdpl(namespace)
    if not osdpl:
        return
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    if not osdplst.exists():
        return

    application, component = health.ident(meta)
    if reason == "delete":
        osdplst.remove_osdpl_service_health(application, component)
        return
    res_health = health.health_status(kube.resource(kwargs["body"]))
    prev_res_health = utils.get_in(
        osdplst.get_osdpl_health(),
        [application, component],
        {"status": ""},
    )
    LOG.debug(
        f"Daemonset {application}-{component} state transition from {prev_res_health['status']} to {res_health}"
    )
    hook = utils.get_in(
        DAEMONSET_HOOKS,
        [
            (prev_res_health["status"], res_health),
            f"{application}-{component}",
        ],
    )
    kwargs["OK_desiredNumberScheduled"] = prev_res_health.get(
        "OK_desiredNumberScheduled", 0
    )
    if hook:
        LOG.debug(f"Daemonset {application}-{component} awaiting hook")
        asyncio.run(hook(osdpl, name, namespace, meta, **kwargs))


@kopf.daemon(*kube.OpenStackDeployment.kopf_on_args)
def batch_health_updater(stopped, **kwargs):
    LOG.info("Batch health updater started")
    while not stopped:
        batch_health.update_health_statuses()
        stopped.wait(settings.OSCTL_BATCH_HEATH_UPDATER_PERIOD)
