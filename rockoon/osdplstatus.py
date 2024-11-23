import logging

import pykube
import datetime
import kopf

from rockoon import settings
from rockoon import version
from rockoon import layers
from rockoon import kube
from rockoon import utils

LOG = logging.getLogger(__name__)


# When start applying changes
APPLYING = "APPLYING"
# When changes are applied
APPLIED = "APPLIED"
# When start deleting service
DELETING = "DELETING"
# When waiting for Applying changes, ie waiting other services to upgrade
WAITING = "WAITING"


class OpenStackDeploymentStatus(pykube.objects.NamespacedAPIObject):
    version = "lcm.mirantis.com/v1alpha1"
    kind = "OpenStackDeploymentStatus"
    endpoint = "openstackdeploymentstatus"
    kopf_on_args = *version.split("/"), endpoint

    def __init__(self, name, namespace, *args, **kwargs):
        kube_api = kube.kube_client()
        self.dummy = {
            "apiVersion": self.version,
            "kind": self.kind,
            "metadata": {"name": name, "namespace": namespace},
            "spec": {},
            "status": {},
        }
        return super().__init__(kube_api, self.dummy)

    def present(self, osdpl_obj):
        if not self.exists():
            self.create()
        kopf.adopt(self.obj, osdpl_obj)
        self.update()

    def absent(self):
        if self.exists():
            self.delete()

    def set_osdpl_state(self, state):
        self.patch({"status": {"osdpl": {"state": state}}})

    def _generate_osdpl_status_generic(self, mspec):
        timestamp = datetime.datetime.utcnow()
        osdpl_generic = {
            "openstack_version": mspec["openstack_version"],
            "controller_version": version.release_string,
            "fingerprint": layers.spec_hash(mspec),
            "timestamp": str(timestamp),
        }
        if settings.OSCTL_CLUSTER_RELEASE:
            osdpl_generic["release"] = settings.OSCTL_CLUSTER_RELEASE
        return osdpl_generic

    def set_osdpl_status(self, state, mspec, osdpl_diff, osdpl_cause):
        patch = self._generate_osdpl_status_generic(mspec)
        patch["changes"] = str(osdpl_diff)
        patch["cause"] = osdpl_cause
        patch["state"] = state
        self.patch({"status": {"osdpl": patch}})

    def get_osdpl_status(self):
        self.reload()
        return self.obj["status"]["osdpl"]["state"]

    def set_service_status(self, service_name, state, mspec):
        patch = self._generate_osdpl_status_generic(mspec)
        patch["state"] = state
        self.patch({"status": {"services": {service_name: patch}}})

    def get_credentials_rotation_status(self, group_name):
        self.reload()
        return utils.get_in(
            self.obj["status"], ["credentials", "rotation", group_name], {}
        )

    def set_credentials_rotation_status(self, group_name, rotation_ts):
        """
        Set credentials rotation timestamp in format %Y-%m-%d %H:%M:%S.%f

        :param group_name: string name of credentials group
        :param rotation_ts: float unix timestamp
        """
        date_obj = datetime.datetime.fromtimestamp(rotation_ts)
        patch = {"timestamp": date_obj.strftime("%Y-%m-%d %H:%M:%S.%f")}
        self.patch(
            {"status": {"credentials": {"rotation": {group_name: patch}}}}
        )

    def set_service_state(self, service_name, state):
        self.patch({"status": {"services": {service_name: {"state": state}}}})

    def remove_service_status(self, service_name):
        self.patch({"status": {"services": {service_name: None}}})

    def set_osdpl_health(self, health):
        self.patch({"status": {"health": health}})

    def get_osdpl_health(self):
        self.reload()
        return self.obj["status"]["health"]

    def remove_osdpl_service_health(self, application, component):
        self.patch({"status": {"health": {application: {component: None}}}})

    def get_osdpl_fingerprint(self):
        self.reload()
        return self.obj["status"]["osdpl"]["fingerprint"]

    def get_osdpl_controller_version(self):
        self.reload()
        return self.obj["status"]["osdpl"]["controller_version"]

    @property
    def osdpl_health(self):
        self.reload()
        return self.obj["status"]["osdpl"]["health"]

    @osdpl_health.setter
    def osdpl_health(self, value):
        self.patch({"status": {"osdpl": {"health": value}}})

    @property
    def osdpl_lcm_progress(self):
        self.reload()
        return self.obj["status"]["osdpl"]["lcm_progress"]

    @osdpl_lcm_progress.setter
    def osdpl_lcm_progress(self, value):
        self.patch({"status": {"osdpl": {"lcm_progress": value}}})

    def update_osdpl_lcm_progress(self):
        self.reload()
        not_ready = []
        total = len(self.obj["status"]["services"].keys())
        osdpl_status = self.obj["status"]["osdpl"]
        for service, status in self.obj["status"]["services"].items():
            if (
                osdpl_status["fingerprint"] != status["fingerprint"]
                or osdpl_status["controller_version"]
                != status["controller_version"]
                or status["state"] != APPLIED
            ):
                not_ready.append(service)
        ready = total - len(not_ready)
        lcm_progress = f"{ready}/{total}"
        self.patch({"status": {"osdpl": {"lcm_progress": lcm_progress}}})
