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
{{ if .Values.conf.neutron.DEFAULT.support_sync_ha_routers_info }}
echo "started" > {{ .Values.conf.neutron.DEFAULT.state_path }}/sync_ha_routers_info
{{ end }}

# Drop all keepalived pid files, we know for sure they are not running.
rm -rf {{ .Values.conf.neutron.DEFAULT.state_path }}/ha_confs/*.pid.*

{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "neutron" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
exec neutron-l3-agent \
      --config-file /etc/neutron/neutron.conf \
{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
      --config-file /tmp/pod-shared/neutron-agent.ini \
{{- end }}
      --config-file /etc/neutron/l3_agent.ini
