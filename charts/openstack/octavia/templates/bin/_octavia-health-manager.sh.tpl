#!/bin/bash

{{/*
Copyright 2019 Samsung Electronics Co., Ltd.

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
{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "octavia" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
COMMAND="${@:-start}"

function start () {

{{- if not ( eq .Values.network.core_plugin "tungstenfabric" ) }}
  # NOTE(vsaienko) flush ip in case they were changed or previous assigned
  ip addr flush dev o-hm0

  source /etc/octavia/updated_conf/ports_configs
  HM_PORT_ADDRS="PORT_ADDRS_${HOSTNAME//-/_}"

  for addr in ${!HM_PORT_ADDRS}; do
    ip addr add $addr dev o-hm0
  done
{{- end }}

  exec octavia-health-manager \
        --config-file /etc/octavia/octavia.conf --config-file /etc/octavia/updated_conf/settings.conf
}

function stop () {
  kill $(pidof -x octavia-health-manager)
}

$COMMAND
