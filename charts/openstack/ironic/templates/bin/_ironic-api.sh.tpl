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

set -ex
{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "ironic" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
COMMAND="${@:-start}"

function start () {
  confs="--config-file /etc/ironic/ironic.conf"
{{- if and (.Values.bootstrap.object_store.enabled) (.Values.bootstrap.object_store.openstack.enabled) }}
  confs+=" --config-file /tmp/pod-shared/swift.conf"
{{- end }}
{{- if and (.Values.bootstrap.network.enabled) (.Values.bootstrap.network.openstack.enabled) }}
  confs+=" --config-file /tmp/pod-shared/networks.conf"
{{- end }}

  IRONIC_API=""
  {{- if not .Values.conf.software.uwsgi.enabled }}
  IRONIC_API="$(type -p ironic-api || true)"
  {{- end }}
  if [ -n "$IRONIC_API" ]; then
    exec ironic-api $confs
  else
    exec uwsgi --ini /etc/ironic/ironic-api-uwsgi.ini --pyargv " $confs "
  fi
}

function stop () {
  kill -TERM 1
}

$COMMAND
