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
from rockoon import exception


class IronicValidator(base.BaseValidator):
    service = "baremetal"

    def validate(self, review_request):
        spec = review_request.get("object", {}).get("spec", {})
        if not spec.get("features", {}).get("ironic", {}):
            raise exception.OsDplValidationFailed(
                "Malformed OpenStackDeployment spec, if baremetal is enabled, "
                "you need to specify its config."
            )
