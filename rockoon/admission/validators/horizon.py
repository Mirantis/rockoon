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


class HorizonValidator(base.BaseValidator):
    service = "dashboard"

    def validate(self, review_request):
        horizon_section = review_request["object"]["spec"]["features"].get(
            "horizon", {}
        )

        themes = horizon_section.get("themes", [])

        for theme in themes:
            if theme.get("enabled", True):
                missing_keys = []
                for key in ["url", "description", "sha256summ", "name"]:
                    if key not in theme:
                        missing_keys.append(key)
                if missing_keys:
                    raise exception.OsDplValidationFailed(
                        "Horion theme is missing mandatory keys {missing_keys}"
                    )
