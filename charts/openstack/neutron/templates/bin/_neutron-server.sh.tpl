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

def_umask=$(umask)
# Mask permissions to files 416 dirs 0750
umask 0027

{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "neutron" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
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

  add_config="neutron.conf;"
{{- if ( has "ovn" .Values.network.backend ) }}
  add_config+='/tmp/pod-shared/neutron-ovn.ini;'
{{- end }}
{{- if .Values.manifests.certificates }}
{{- if ( has "tungstenfabric" .Values.network.backend ) }}
  add_config+='plugins/tungstenfabric/tf_plugin.ini;'
{{- else }}
  add_config+='plugins/ml2/ml2_conf.ini;'
{{- end }}
{{- if .Values.conf.plugins.taas.taas.enabled }}
  add_config+='taas_plugin.ini;'
{{- end }}
{{- if ( has "sriovnicswitch" .Values.network.backend ) }}
  add_config+='plugins/ml2/sriov_agent.ini;'
{{- end }}
{{- if .Values.conf.plugins.l2gateway }}
  add_config+='l2gw_plugin.ini;'
{{- end }}

  export OS_NEUTRON_CONFIG_FILES=${add_config}

  for WSGI_SCRIPT in neutron-api; do
    cp -a $(type -p ${WSGI_SCRIPT}) /var/www/cgi-bin/neutron/
  done

  if [ -f /etc/apache2/envvars ]; then
    # Loading Apache2 ENV variables
    source /etc/apache2/envvars
    mkdir -p ${APACHE_RUN_DIR}
  fi

{{- if .Values.conf.software.apache2.a2enmod }}
  {{- range .Values.conf.software.apache2.a2enmod }}
  a2enmod {{ . }}
  {{- end }}
{{- end }}

{{- if .Values.conf.software.apache2.a2ensite }}
  {{- range .Values.conf.software.apache2.a2ensite }}
  a2ensite {{ . }}
  {{- end }}
{{- end }}

{{- if .Values.conf.software.apache2.a2dismod }}
  {{- range .Values.conf.software.apache2.a2dismod }}
  a2dismod {{ . }}
  {{- end }}
{{- end }}

  if [ -f /var/run/apache2/apache2.pid ]; then
    # Remove the stale pid for debian/ubuntu images
    rm -f /var/run/apache2/apache2.pid
  fi

  umask ${def_umask}

  # Starts Apache2
  exec {{ .Values.conf.software.apache2.binary }} {{ .Values.conf.software.apache2.start_parameters }}
{{- else }}
  exec neutron-server \
        --config-file /etc/neutron/neutron.conf
{{- if ( has "ovn" .Values.network.backend ) }} \
       --config-file /tmp/pod-shared/neutron-ovn.ini
{{- end }}
{{- if eq .Values.network.core_plugin "tungstenfabric" }} \
        --config-file /etc/neutron/plugins/tungstenfabric/tf_plugin.ini
{{- else }} \
        --config-file /etc/neutron/plugins/ml2/ml2_conf.ini
{{- end }}
{{- if .Values.conf.plugins.taas.taas.enabled }} \
        --config-file /etc/neutron/taas_plugin.ini
{{- end }}
{{- if ( has "sriovnicswitch" .Values.network.backend ) }} \
        --config-file /etc/neutron/plugins/ml2/sriov_agent.ini
{{- end }}
{{- if .Values.conf.plugins.l2gateway }} \
        --config-file /etc/neutron/l2gw_plugin.ini
{{- end }}
{{- end }}
}

function stop () {
{{- if .Values.manifests.certificates }}
  if [ -f /etc/apache2/envvars ]; then
    source /etc/apache2/envvars
  fi
  {{ .Values.conf.software.apache2.binary }} -k graceful-stop
{{- else }}
  kill -TERM 1
{{- end }}
}

$COMMAND
