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


class DatabaseValidator(base.BaseValidator):
    service = "database"

    def validate(self, review_request):
        db_section = (
            review_request.get("object", {})
            .get("spec", {})
            .get("features", {})
            .get("database", {})
        )
        self._check_backup_backend(db_section)
        self._check_backup_sync(db_section)

    def _check_backup_backend(self, db_section):
        backup_section = db_section.get("backup", {})
        if backup_section.get(
            "backend", "pvc"
        ) == "pv_nfs" and not backup_section.get("pv_nfs", {}):
            raise exception.OsDplValidationFailed(
                "When backup backend is set to pv_nfs, pv_nfs.server and pv_nfs.path options are required"
            )

    def _check_backup_sync(self, db_section):
        def _check_fields(data_name, data, fields, section=None):
            checked = data
            msg = f"{data_name} fields {fields} are mandatory"
            if section:
                checked = data[section]
                msg = f"{data_name} section {section} fields {fields} are mandatory"
            for field in fields:
                if field not in checked.keys():
                    raise exception.OsDplValidationFailed(msg)

        sync_section = db_section.get("backup", {}).get("sync_remote", {})
        sync_enabled = sync_section.get("enabled", False)
        sync_remotes = sync_section.get("remotes", {})
        if sync_enabled:
            if len(sync_remotes.keys()) > 1:
                raise exception.OsDplValidationFailed(
                    "Only one remote is allowed in remotes section"
                )

            for name, remote in sync_remotes.items():
                _check_fields(f"Remote {name}", remote, ["conf", "path"])

                conf = remote["conf"]
                conf_required = ["type"]
                type_required = []
                extra_required = []

                if conf.get("type", "") == "s3":
                    type_required = [
                        "provider",
                        "access_key_id",
                        "secret_access_key",
                    ]
                    if conf.get("provider", "") == "Ceph":
                        extra_required.append("endpoint")

                conf_required.extend(type_required)
                conf_required.extend(extra_required)

                _check_fields(
                    f"Remote {name}", remote, conf_required, section="conf"
                )
