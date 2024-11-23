# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy

from rockoon.admission.validators import base
from rockoon import constants
from rockoon import exception
from rockoon import osdplstatus
from rockoon import kube
from rockoon.utils import CronValidator, get_in


class OpenStackValidator(base.BaseValidator):
    """Validates general sanity of OpenStackDeployment"""

    service = "openstack"

    def validate(self, review_request):
        old_obj = review_request.get("oldObject", {})
        new_obj = review_request.get("object", {})
        self._deny_master(new_obj)
        if review_request["operation"] == "CREATE":
            osdpl = kube.get_osdpl()
            if osdpl and osdpl.exists():
                raise exception.OsDplValidationFailed(
                    "OpenStackDeployment already exist in namespace "
                    "only one resource can be created"
                )

        if review_request["operation"] == "UPDATE":
            if self._openstack_version_changed(old_obj, new_obj):
                # on update we deffinitely have both old and new as not empty
                self._validate_openstack_upgrade(old_obj, new_obj)
                self._validate_for_another_upgrade(review_request)
        self._check_masakari_allowed(new_obj)
        self._check_baremetal_allowed(new_obj)
        self._check_panko_allowed(new_obj)
        self._check_manila_allowed(new_obj)
        self._deny_encrypted_api_key(new_obj)
        self._deny_strict_admin_policy(new_obj)
        self._check_schedules(new_obj)

    def validate_status(self, review_request):
        old_obj = review_request.get("oldObject", {})
        new_obj = review_request.get("object", {})
        self._validate_credentials(old_obj, new_obj, review_request)

    def validate_delete(self, review_request):
        self._check_delete_allowed(review_request)

    def _deny_master(self, new_obj):
        new_version = new_obj.get("spec", {}).get("openstack_version")
        if new_version == "master":
            raise exception.OsDplValidationFailed(
                "Using master of OpenStack is not permitted. "
                "You must disable the OpenStackDeployment admission "
                "controller to deploy, use or upgrade to master."
            )

    def _check_masakari_allowed(self, new_obj):
        # Do not call heavy render logic, assume default values in preset is ok
        openstack_services = (
            new_obj.get("spec", {}).get("features", {}).get("services", [])
        )
        os_num_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ].value
        if (
            "instance-ha" in openstack_services
            and os_num_version < constants.OpenStackVersion["victoria"].value
        ):
            raise exception.OsDplValidationFailed(
                "This set of services is not permitted to use with"
                "current OpenStack version."
            )

    def _check_baremetal_allowed(self, new_obj):
        preset = new_obj["spec"]["preset"]
        if (
            "baremetal" in new_obj["spec"]["features"].get("services", [])
            and preset == "compute-tf"
        ):
            raise exception.OsDplValidationFailed(
                "This OpenStack Baremetal services is not supported"
                "with TungstenFabric networking."
            )

    def _check_panko_allowed(self, new_obj):
        # Do not call heavy render logic, assume default values in preset is ok
        openstack_services = (
            new_obj.get("spec", {}).get("features", {}).get("services", [])
        )
        os_num_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ].value
        if (
            "event" in openstack_services
            and os_num_version >= constants.OpenStackVersion["xena"].value
        ):
            raise exception.OsDplValidationFailed(
                "Event service (Panko) was retired and "
                "is not available since OpenStack Xena release."
            )

    def _openstack_version_changed(self, old_obj, new_obj):
        old_version = constants.OpenStackVersion[
            old_obj["spec"]["openstack_version"]
        ]
        new_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ]
        return new_version != old_version

    def _is_osdpl_locked(self, review_request):
        osdplst = osdplstatus.OpenStackDeploymentStatus(
            review_request["name"], review_request["namespace"]
        )
        osdplst_status = osdplst.get_osdpl_status()
        if osdplst_status != osdplstatus.APPLIED:
            return True

    def _validate_for_another_upgrade(self, review_request):
        if self._is_osdpl_locked(review_request):
            raise exception.OsDplValidationFailed(
                "OpenStack version upgrade is not possible while another upgrade is in progress."
            )

    def _upgrade_max_distance(self, new_version):
        # Calculation of the allowed upgrade level for OpenStack releases
        slurp_releases = constants.SLURP_RELEASES
        if (
            new_version in slurp_releases
            and slurp_releases.index(new_version) != 0
        ):
            new_version_index = slurp_releases.index(new_version)
            allowed_from = slurp_releases[new_version_index - 1]
            return (
                constants.OpenStackVersion[new_version].value
                - constants.OpenStackVersion[allowed_from].value
            )
        else:
            return 1

    def _validate_openstack_upgrade(self, old_obj, new_obj):
        # NOTE(pas-ha) this logic relies on 'master' already has been denied
        old_version = constants.OpenStackVersion[
            old_obj["spec"]["openstack_version"]
        ]
        new_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ]
        if old_version > new_version:
            raise exception.OsDplValidationFailed(
                "OpenStack version downgrade is not permitted"
            )
        if new_version.value - old_version.value > self._upgrade_max_distance(
            new_version.name
        ):
            raise exception.OsDplValidationFailed(
                f"Skip-level OpenStack version upgrade is not permitted between {old_version.name} and {new_version.name}"
            )

        # validate that nothing else is changed together with
        # openstack_version
        _old_spec = copy.deepcopy(old_obj["spec"])
        _old_spec.pop("openstack_version")
        _new_spec = copy.deepcopy(new_obj["spec"])
        _new_spec.pop("openstack_version")
        if _new_spec != _old_spec:
            raise exception.OsDplValidationFailed(
                "If spec.openstack_version is changed, "
                "changing other values in the spec is not permitted."
            )

    def _validate_credentials(self, old_obj, new_obj, review_request):
        _old_status = copy.deepcopy(old_obj.get("status", {}))
        _old_credentials = _old_status.get("credentials", {})
        _new_status = copy.deepcopy(new_obj.get("status", {}))
        _new_credentials = _new_status.get("credentials", {})

        if _new_credentials != _old_credentials:
            if self._is_osdpl_locked(review_request):
                raise exception.OsDplValidationFailed(
                    "OpenStack credentials update is not possible while another operation is in progress."
                )

            for group_name, group in _old_credentials.items():
                if "rotation_id" not in group.keys():
                    return

                new_rotation_id = get_in(
                    _new_credentials,
                    [group_name, "rotation_id"],
                    0,
                )
                if not new_rotation_id:
                    raise exception.OsDplValidationFailed(
                        f"Removing {group_name} rotation config is not allowed"
                    )

            for group_name, group in _new_credentials.items():
                # in future it is possible there can be other options except rotation_id
                if "rotation_id" not in group.keys():
                    return

                old_rotation_id = get_in(
                    _old_credentials,
                    [group_name, "rotation_id"],
                    0,
                )
                new_rotation_id = group["rotation_id"]

                if new_rotation_id <= 0:
                    raise exception.OsDplValidationFailed(
                        f"{group_name} rotation_id should be greater than 0"
                    )
                elif old_rotation_id > new_rotation_id:
                    raise exception.OsDplValidationFailed(
                        f"Decreasing {group_name} rotation_id is not allowed"
                    )
                elif new_rotation_id - old_rotation_id > 1:
                    raise exception.OsDplValidationFailed(
                        f"Increasing {group_name} rotation_id more than by 1 is not allowed"
                    )

    def _check_delete_allowed(self, review_request):
        if self._is_osdpl_locked(review_request):
            raise exception.OsDplValidationFailed(
                "OpenStack deletion is not allowed, while OpenStackDeploymentStatus is in transit state."
            )

    def _deny_encrypted_api_key(self, new_obj):
        api_key = (
            new_obj.get("spec", {})
            .get("features", {})
            .get("ssl", {})
            .get("public_endpoints", {})
            .get("api_key", "")
        )
        if "BEGIN ENCRYPTED PRIVATE KEY" in api_key:
            raise exception.OsDplValidationFailed(
                "Encrypted SSL key is not allowed yet. To use SSL "
                "the key must be not encrypted."
            )

    def _deny_strict_admin_policy(self, new_obj):
        strict_admin_policy = (
            new_obj["spec"]
            .get("features", {})
            .get("policies", {})
            .get("strict_admin", {})
        )
        os_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ]
        if (
            strict_admin_policy.get("enabled")
            and os_version < constants.OpenStackVersion.yoga
        ):
            raise exception.OsDplValidationFailed(
                "Strict admin policy is allowed only from Yoga release."
            )

    def _check_schedules(self, new_obj):
        cleaners = (
            new_obj.get("spec", {})
            .get("features", {})
            .get("database", {})
            .get("cleanup", {})
        )
        if cleaners:
            for cleaner_cron in [
                "barbican",
                "masakari",
                "nova",
                "cinder",
                "glance",
                "heat",
                "aodh",
                "manila",
            ]:
                schedule = cleaners.get(cleaner_cron, {}).get("schedule")
                if schedule:
                    if not CronValidator(schedule).validate():
                        raise exception.OsDplValidationFailed(
                            f"Schedule string '{schedule}' has wrong values. Please recheck them."
                        )
        backup = (
            new_obj.get("spec", {})
            .get("features", {})
            .get("database", {})
            .get("backup", {})
            .get("schedule_time")
        )
        if backup:
            if not CronValidator(backup).validate():
                raise exception.OsDplValidationFailed(
                    f"Schedule string '{backup}' has wrong values. Please recheck them."
                )

    def _check_manila_allowed(self, new_obj):
        preset = new_obj["spec"]["preset"]
        openstack_services = (
            new_obj.get("spec", {}).get("features", {}).get("services", [])
        )
        os_num_version = constants.OpenStackVersion[
            new_obj["spec"]["openstack_version"]
        ].value
        if (
            "shared-file-system" in openstack_services
            and preset == "compute-tf"
        ):
            raise exception.OsDplValidationFailed(
                "Shared Filesystems (Manila) services is not supported"
                "with TungstenFabric networking."
            )
        if (
            "shared-file-system" in openstack_services
            and os_num_version < constants.OpenStackVersion["yoga"].value
        ):
            raise exception.OsDplValidationFailed(
                "Shared Filesystems (Manila) does not supported "
                "in OpenStack version before Yoga release."
            )
