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

import os
from jsonschema import validate
import yaml

from rockoon.admission.validators import base
from rockoon import exception

SCHEMA_FILE = "../schemas/nodes.yaml"
SCHEMA = yaml.safe_load(
    open(os.path.join(os.path.abspath(os.path.dirname(__file__)), SCHEMA_FILE))
)


class NodeSpecificValidator(base.BaseValidator):
    service = "nodes"

    def validate(self, review_request):
        node_specific = (
            review_request.get("object", {}).get("spec", {}).get("nodes", {})
        )
        try:
            validate(instance=node_specific, schema=SCHEMA)
        except Exception as e:
            raise exception.OsDplValidationFailed(
                f"The spec:nodes format is invalid. Failed to validate schema: {e}"
            )
