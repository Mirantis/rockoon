from rockoon import utils
from rockoon import settings
from jinja2.exceptions import TemplateRuntimeError


@utils.log_exception_and_raise
def substitute_local_proxy_hostname(url, hostname):
    return utils.substitute_local_proxy_hostname(url, hostname)


def raise_error(msg):
    raise TemplateRuntimeError(msg)


@utils.log_exception_and_raise
def namespaces(names):
    all_namespaces = {
        "os_deployment": settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
        "ceph_shared": settings.OSCTL_CEPH_SHARED_NAMESPACE,
        "redis_deployment": settings.OSCTL_REDIS_NAMESPACE,
        "os_controller": settings.OSCTL_CONTROLLER_NAMESPACE,
        "ceph_deployment": settings.OSCTL_CEPH_DEPLOYMENT_NAMESPACE,
        "lma_deployment": settings.OSCTL_LMA_DEPLOYMENT_NAMESPACE,
        "tf_deployment": settings.OSCTL_TF_DEPLOYMENT_NAMESPACE,
    }
    return [v for k, v in all_namespaces.items() if k in names]
