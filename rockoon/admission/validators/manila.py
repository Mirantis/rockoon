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


class ManilaValidator(base.BaseValidator):
    service = "shared-file-system"

    def validate(self, review_request):
        spec = review_request.get("object", {}).get("spec", {})
        manila_section = spec.get("features", {}).get("manila", {})

        self._check_share_backend(manila_section)

    def _check_share_backend(self, manila_section):
        backend_section = manila_section.get("share", {}).get("backends", {})
        for name, opts in backend_section.items():
            if opts.get("enabled", True):
                enabled_backends = [
                    x
                    for x in (
                        opts["values"]["conf"]
                        .get("manila", {})
                        .get("DEFAULT", {})
                        .get("enabled_share_backends", "")
                        .split(",")
                    )
                    if x
                ]
                if not enabled_backends:
                    raise exception.OsDplValidationFailed(
                        f"Param 'enabled_share_backends' should be specified in DEFAULT section for Manila backend {name}."
                    )
                for backend in enabled_backends:
                    backend_conf = opts["values"]["conf"]["manila"].get(
                        backend, {}
                    )
                    if backend_conf.get("share_backend_name") is None:
                        raise exception.OsDplValidationFailed(
                            f"Param 'share_backend_name' should be specified in {backend} section for Manila backend {name}."
                        )
                    if backend_conf.get("share_driver") is None:
                        raise exception.OsDplValidationFailed(
                            f"Param 'share_driver' should be specified in {backend} section for Manila backend {name}."
                        )
