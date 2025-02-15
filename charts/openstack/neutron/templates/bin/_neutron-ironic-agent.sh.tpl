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
{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "neutron" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
COMMAND="${@:-start}"

function start () {
  def_umask=$(umask)
  # Mask permissions to files 416 dirs 0750
  umask 0027

{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
  mkdir -p /tmp/pod-shared
  tee > /tmp/pod-shared/neutron-agent.ini << EOF
[DEFAULT]
host = $(hostname --fqdn)
EOF
{{- end }}

  umask ${def_umask}

  exec ironic-neutron-agent \
        --config-file /etc/neutron/neutron.conf \
{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
  --config-file /tmp/pod-shared/neutron-agent.ini \
{{- end }}
        --config-file /etc/neutron/plugins/ml2/ml2_conf.ini
}

function stop () {
  kill -TERM 1
}

$COMMAND
