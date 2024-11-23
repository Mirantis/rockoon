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
import yaml
from jsonschema import validate

from rockoon import exception


class BaseValidator(object):
    service = None

    def validate(self, review_request):
        raise NotImplementedError()

    def validate_delete(self, review_request):
        pass


def validate_schema(schema_file, obj):
    schema_file = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "schemas", schema_file
    )
    with open(schema_file) as f:
        schema = yaml.safe_load(f)
    try:
        validate(instance=obj, schema=schema)
    except Exception as e:
        raise exception.OsDplValidationFailed(
            f"Failed to validate schema {schema_file}: {e}"
        )
