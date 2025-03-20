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

from rockoon.admission.validators import base
from rockoon import constants
from rockoon import exception


class NovaValidator(base.BaseValidator):
    service = "compute"

    def validate(self, review_request):
        os_num_version = constants.OpenStackVersion[
            review_request["object"]["spec"]["openstack_version"]
        ].value
        nova_section = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("nova", {})
        )
        self._check_ephemeral_encryption(nova_section)
        self._check_vcpu_type(nova_section, os_num_version)
        self._check_db_cleanup(review_request, os_num_version)

    def _check_ephemeral_encryption(self, nova_section):
        if (
            nova_section.get("images", {})
            .get("encryption", {})
            .get("enabled", False)
            and nova_section.get("images", {}).get("backend") != "lvm"
        ):
            raise exception.OsDplValidationFailed(
                "Ephemeral encryption is supported only with LVM backend."
            )

    def _check_vcpu_type(self, nova_section, os_version):
        vcpu_types = nova_section.get("vcpu_type", "").split(",")

        if len(vcpu_types) > 1:
            if "host-model" in vcpu_types or "host-passthrough" in vcpu_types:
                raise exception.OsDplValidationFailed(
                    "Vcpu type 'host-model' or 'host-passthrough' "
                    "can not be used together with other values."
                )
            if os_version < constants.OpenStackVersion["train"].value:
                raise exception.OsDplValidationFailed(
                    "Multiple vcpu types are supported "
                    "since OpenStack Train release."
                )

    def _check_db_cleanup(self, review_request, os_version):
        nova_db_cleanup = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("database", {})
            .get("cleanup", {})
            .get("nova", {})
        )
        if (
            nova_db_cleanup.get("enabled")
            and os_version < constants.OpenStackVersion["antelope"].value
        ):
            raise exception.OsDplValidationFailed(
                "Nova db cleanup is supported "
                "since OpenStack Antelope release."
            )
