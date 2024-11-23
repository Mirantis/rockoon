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


class GlanceValidator(base.BaseValidator):
    service = "image"

    def validate(self, review_request):
        spec = review_request.get("object", {}).get("spec", {})
        glance_features = spec.get("features", {}).get("glance", {})
        if (
            glance_features.get("signature", {}).get(
                "certificate_validation", False
            )
            and glance_features.get("signature", {}).get("enabled", False)
            == False
        ):
            raise exception.OsDplValidationFailed(
                "The certificate validation might be enabled only with signature validation."
            )

        self.validate_glance_backends(glance_features)

    def validate_glance_backends(self, glance_features):

        cinder_backends = glance_features.get("backends", {}).get("cinder", {})
        file_backends = glance_features.get("backends", {}).get("file", {})
        all_backends = []
        for backend_type, backends in glance_features.get(
            "backends", {}
        ).items():
            for name, opts in backends.items():
                all_backends.append(opts)

        is_default_seen = False
        if not all_backends:
            return
        for backend_name, opts in cinder_backends.items():
            if ("cinder_volume_type" in opts and "backend_name" in opts) or (
                "cinder_volume_type" not in opts and "backend_name" not in opts
            ):
                raise exception.OsDplValidationFailed(
                    "Either cinder_volume_type or backend_name should be configured for glance backend."
                )
            if "backend_name" in opts:
                if len(opts["backend_name"].split(":")) != 2:
                    raise exception.OsDplValidationFailed(
                        "Glance cinder backend_name should be in the following format "
                        "<cinder backend type>:<cinder volume type>"
                    )
        # Ensure only one backend is configured with default=True
        for opts in all_backends:
            if is_default_seen is False:
                is_default_seen = opts.get("default", False)
            elif opts.get("default", False):
                raise exception.OsDplValidationFailed(
                    "Malformed OpenStackDeployment spec, only one glance backend"
                    f"might be configured as default."
                )
        if is_default_seen is False:
            raise exception.OsDplValidationFailed(
                "Glance backend should have at least one default backend."
            )

        if len(file_backends.keys()) >= 2:
            raise exception.OsDplValidationFailed(
                "Only one file backend supported at the moment"
            )
        for backend_name, backend in file_backends.items():
            pvc = backend["pvc"]
            missing = []
            for mandatory_key in ["storage_class_name", "size"]:
                if mandatory_key not in pvc:
                    missing.append(mandatory_key)
            if missing:
                raise exception.OsDplValidationFailed(
                    "Glance file backend has missing mandatory keys %s",
                    missing,
                )
