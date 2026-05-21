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
COMMAND="${@:-start}"

function start () {

mkdir -p /tmp/pod-shared
{{- if ( has "ovn" .Values.network.backend ) }}
# NOTE(vsaienko): unless PRODX-24795 is fixed Pick IP on the start
ovn_db_host={{ tuple "ovn_db" "internal" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }}
ovn_db_ip=$(dig ${ovn_db_host} +short)
ovn_db_proto={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.keystone_endpoint_scheme_lookup" }}
ovn_db_nb_port={{ tuple "ovn_db" "internal" "nb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
ovn_db_sb_port={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
if [[ -z $ovn_db_ip ]]; then
  echo "Can't resolve ovn-db service IP"
  exit 1
fi

tee > /tmp/pod-shared/neutron-ovn.ini << EOF
[DEFAULT]
host = $NODE_NAME

[ovn]
ovn_nb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_nb_port}
ovn_sb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_sb_port}
EOF
cat /tmp/pod-shared/neutron-ovn.ini
{{- end }}

confs="--config-file /etc/neutron/neutron.conf"
{{- if ( has "ovn" .Values.network.backend ) }}
  confs+=" --config-file /tmp/pod-shared/neutron-ovn.ini"
{{- end }}
{{- if eq .Values.network.core_plugin "tungstenfabric" }}
  confs+=" --config-file /etc/neutron/plugins/tungstenfabric/tf_plugin.ini"
{{- else }}
  confs+=" --config-file /etc/neutron/plugins/ml2/ml2_conf.ini"
{{- end }}
{{- if .Values.conf.plugins.taas.taas.enabled }}
  confs+=" --config-file /etc/neutron/taas_plugin.ini"
{{- end }}
{{- if ( has "sriovnicswitch" .Values.network.backend ) }}
  confs+=" --config-file /etc/neutron/plugins/ml2/sriov_agent.ini"
{{- end }}
{{- if .Values.conf.plugins.l2gateway }}
  confs+=" --config-file /etc/neutron/l2gw_plugin.ini"
{{- end }}

  exec neutron-rpc-server $confs
}

function stop () {
  kill -TERM 1
}

$COMMAND
