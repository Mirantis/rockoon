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


class BarbicanValidator(base.BaseValidator):
    service = "key-manager"

    def validate(self, review_request):
        barbican_section = review_request["object"]["spec"]["features"].get(
            "barbican", {}
        )
        os_num_version = constants.OpenStackVersion[
            review_request["object"]["spec"]["openstack_version"]
        ].value

        vault_settings = barbican_section.get("backends", {}).get("vault", {})

        if (
            vault_settings.get("enabled", False)
            and vault_settings.get("namespace")
            and os_num_version < constants.OpenStackVersion["victoria"].value
        ):
            raise exception.OsDplValidationFailed(
                "Vault namespaces are supported only starting from "
                "Victoria openstack_version."
            )
