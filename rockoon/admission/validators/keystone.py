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


class KeystoneValidator(base.BaseValidator):
    service = "identity"

    def validate(self, review_request):
        keycloak_section = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("keystone", {})
            .get("keycloak", {})
        )
        if (
            keycloak_section.get("enabled", False)
            and keycloak_section.get("url") is None
        ):
            raise exception.OsDplValidationFailed(
                "Malformed OpenStackDeployment spec, if keycloak is "
                "enabled for identity service, you need to specify url."
            )

        domain_specific_config = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("keystone", {})
            .get("domain_specific_configuration", {})
        )
        if "ks_domains" in domain_specific_config:
            if "domains" in domain_specific_config:
                raise exception.OsDplValidationFailed(
                    "Defining  both domains and ks_domains not supported, use ks_domains instead."
                )
            mandatory_fields = ["config", "enabled"]
            for field in mandatory_fields:
                for element in domain_specific_config["ks_domains"].values():
                    if field not in element.keys():
                        raise exception.OsDplValidationFailed(
                            "Section ks_domains fields config and enabled are mandatory"
                        )

        federation = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("keystone", {})
            .get("federation", {})
        )
        if federation:
            enabled_providers = [
                x
                for x in federation["openid"]["providers"].values()
                if x.get("enabled", True)
            ]
            if keycloak_section.get("enabled", False) and federation.get(
                "enabled", True
            ):
                raise exception.OsDplValidationFailed(
                    "Use one of keystone:keycloack or keystone:federation section"
                )

            if (
                federation["openid"].get("oidc_auth_type", "oauth20")
                == "oauth20"
            ):
                if len(enabled_providers) > 1:
                    raise exception.OsDplValidationFailed(
                        "Multiple oidc providers supperted only with oauth2 type"
                    )
