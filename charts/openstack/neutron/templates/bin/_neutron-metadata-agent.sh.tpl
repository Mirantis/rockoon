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

set -x

def_umask=$(umask)
# Mask permissions to files 416 dirs 0750
umask 0027

{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "neutron" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
{{- if ( has "ovn" .Values.network.backend ) }}
mkdir -p /tmp/pod-shared
rm -rf /tmp/generic_health_probe_cache
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
[ovn]
ovn_nb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_nb_port}
ovn_sb_connection=${ovn_db_proto}:${ovn_db_ip}:${ovn_db_sb_port}
EOF

METADTA_BINARY=neutron-ovn-metadata-agent
{{- else }}
METADTA_BINARY=neutron-metadata-agent
{{- end }}

umask ${def_umask}

exec ${METADTA_BINARY} \
      --config-file /etc/neutron/neutron.conf \
{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
      --config-file /tmp/pod-shared/neutron-agent.ini \
{{- end }}
{{- if ( has "ovn" .Values.network.backend ) }}
      --config-file /tmp/pod-shared/neutron-ovn.ini \
{{- end }}
      --config-file /etc/neutron/metadata_agent.ini
