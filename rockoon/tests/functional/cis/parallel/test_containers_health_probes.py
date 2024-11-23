import logging
import unittest

from rockoon.tests.functional import base, config
from rockoon import settings, kube, constants

from parameterized import parameterized

LOG = logging.getLogger(__name__)
CONF = config.Config()


def get_objects_for_test():
    kube_api = kube.kube_client()
    check_list = []
    for klass_name in ["StatefulSet", "DaemonSet", "Deployment"]:
        klass = getattr(kube, klass_name)
        objects = klass.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE
        )
        for o in objects:
            for check_type in ["livenessProbe", "readinessProbe"]:
                check_list.append(
                    (check_type, klass_name, o.obj["metadata"]["name"])
                )
    return check_list


def health_check_custom_name_func(testcase_func, param_num, param):
    return "%s_%s" % (
        testcase_func.__name__,
        parameterized.to_safe_name(
            "_".join(str(x).lower() for x in param.args)
        ),
    )


class HealthFunctionalTestCase(base.BaseFunctionalTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        openstack_version = cls.osdpl.obj["spec"]["openstack_version"]
        if (
            constants.OpenStackVersion[openstack_version]
            < constants.OpenStackVersion["yoga"]
        ):
            raise unittest.SkipTest(
                "Skip health probe checking for releases lower than Yoga"
            )

    @parameterized.expand(
        get_objects_for_test,
        skip_on_empty=True,
        name_func=health_check_custom_name_func,
    )
    def test_containers(
        self,
        probe_type,
        klass_name,
        object_name,
        namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
    ):
        failed_containers = []
        klass = getattr(kube, klass_name)
        obj = kube.find(klass, object_name, namespace)
        for container in obj.obj["spec"]["template"]["spec"]["containers"]:
            probe = container.get(f"{probe_type}")
            if not probe:
                failed_containers.append(container["name"])
        assert (
            not failed_containers
        ), f"Container(s) {failed_containers} in {klass_name}/{object_name} have no {probe_type}."
