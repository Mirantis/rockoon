#!/bin/sh
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

{{- $mysql := .Values.conf.mysql.client }}
{{- if empty $mysql.port -}}
{{- $_ :=  tuple "oslo_db_powerdns" "internal" "mysql" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | set $mysql "port" -}}
{{- end -}}
set -ex

BACKEND_PORT={{ $mysql.port }}
PDNS_PORT={{ tuple "powerdns" "internal" "powerdns_tcp" . | include "helm-toolkit.endpoints.endpoint_port_lookup" }}
PDNS_PROCESS='pdns_server-instance'

nc -zv 127.0.0.1 "${PDNS_PORT}"

PDNS_PID="$(pidof ${PDNS_PROCESS})"

netstat -ntp | grep " ${PDNS_PID}/" | grep ":${BACKEND_PORT} " | grep ESTABLISHED
