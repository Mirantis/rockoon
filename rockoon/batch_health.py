import collections

from rockoon import constants
from rockoon import health
from rockoon import kube
from rockoon import settings
from rockoon import utils
from rockoon import osdplstatus


LOG = utils.get_logger(__name__)


def get_k8s_objects(
    namespace, types=[kube.Deployment, kube.DaemonSet, kube.StatefulSet]
):
    for t in types:
        for i in kube.resource_list(t, "", namespace):
            yield i


def calculate_status(k8s_object):
    ident = health.ident(k8s_object.metadata)

    health_status = health.health_status(k8s_object)
    return (
        ident,
        (
            health_status,
            utils.get_in(k8s_object.obj, ["status", "observedGeneration"], 0),
        ),
    )


def calculate_statuses(k8s_objects):
    return {k: v for k, v in (calculate_status(i) for i in k8s_objects)}


def get_health_statuses(osdpl):
    if osdpl is None:
        osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)
    statuses = calculate_statuses(get_k8s_objects(osdpl.namespace))
    health_all = collections.defaultdict(dict)
    for ident, status in statuses.items():
        LOG.debug(f"Got status {status} for {ident}")
        health_all[ident[0]][ident[1]] = {
            "status": status[0],
            "generation": status[1],
        }
    return health_all


def remove_stale_statuses(osdplst, statuses):
    patch = {}
    old_statuses = osdplst.get_osdpl_health()
    for service in old_statuses.keys() - statuses.keys():
        patch[service] = None
    for service, components in old_statuses.items():
        patch_components = {}
        if service not in statuses:
            continue
        for component in components.keys():
            if component not in statuses[service]:
                patch_components[component] = None
        if patch_components:
            patch[service] = patch_components
    if patch:
        LOG.info(f"Removing stale health statuses: {patch}")
        osdplst.set_osdpl_health(patch)


def get_overall_health(statuses):
    not_ready = []
    total = len(statuses.keys())
    for service, components in statuses.items():
        for component, component_status in components.items():
            if (
                component_status.get("status")
                == constants.K8sObjHealth.BAD.value
            ):
                not_ready.append(service)
                break
    ready = total - len(not_ready)
    return f"{ready}/{total}"


def update_health_statuses():
    osdpl = kube.get_osdpl(settings.OSCTL_OS_DEPLOYMENT_NAMESPACE)
    osdplst = osdplstatus.OpenStackDeploymentStatus(
        osdpl.name, osdpl.namespace
    )
    statuses = get_health_statuses(osdpl)
    health.set_multi_application_health(osdplst, statuses)
    remove_stale_statuses(osdplst, statuses)
    osdplst.osdpl_health = get_overall_health(statuses)
    LOG.info("Health statuses updated %d", len(statuses))
