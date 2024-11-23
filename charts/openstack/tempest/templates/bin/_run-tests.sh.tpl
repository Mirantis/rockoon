#!/bin/bash

{{/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

set -exo pipefail
{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "tempest" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}

source /tmp/functions.sh

{{ if .Values.conf.cleanup.enabled }}
tempest cleanup --init-saved-state

if [ "true" == "{{- .Values.conf.cleanup.force -}}" ]; then
trap "tempest cleanup; exit" 1 ERR
fi
{{- end }}

# stestr.conf should be in root folder as tempest workspace is root folder by default
STESTR_CONF="/.stestr.conf"
STESTR_CONF_ORIG="/tmp/stestr-orig.conf"

PYTHON_PKG_PATH=$(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")
cp $STESTR_CONF_ORIG $STESTR_CONF

{{- if not (index .Values.conf.stestr.DEFAULT "test_path") }}
iniset $STESTR_CONF DEFAULT test_path ${PYTHON_PKG_PATH}/tempest/test_discover
{{- end }}

{{- if not (index .Values.conf.stestr.DEFAULT "top_dir") }}
iniset $STESTR_CONF DEFAULT top_dir ${PYTHON_PKG_PATH}/tempest
{{- end }}

# write stdout/stderr to file as well
conf_script () {
  {{ .Values.conf.script }}
}
logs=/var/lib/tempest/data/$(date +%Y%m%d_%H%M%S)
mkdir -p $logs
conf_script |& tee $logs/tempest.log

{{ if .Values.conf.cleanup.enabled }}
tempest cleanup
{{- end }}
