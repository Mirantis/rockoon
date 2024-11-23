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
{{ dict "envAll" . "objectType" "script_sh" "secretPrefix" "cinder" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
COMMAND="${@:-start}"

function start () {
  cp -a $(type -p cinder-wsgi) /var/www/cgi-bin/cinder/

  {{- if .Values.conf.software.apache2.a2enmod }}
    {{- range .Values.conf.software.apache2.a2enmod }}
  a2enmod {{ . }}
    {{- end }}
  {{- end }}
  {{- if .Values.conf.software.apache2.a2dismod }}
    {{- range .Values.conf.software.apache2.a2dismod }}
  a2dismod {{ . }}
    {{- end }}
  {{- end }}

  exec {{ .Values.conf.software.apache2.binary }} {{ .Values.conf.software.apache2.start_parameters }}
}

function stop () {
  {{ .Values.conf.software.apache2.binary }} -k graceful-stop
}

if [ -f /etc/apache2/envvars ]; then
   # Loading Apache2 ENV variables
   source /etc/apache2/envvars
fi

$COMMAND
