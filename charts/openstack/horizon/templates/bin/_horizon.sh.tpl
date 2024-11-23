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
{{- $envAll := . }}
COMMAND="${@:-start}"

function start () {

  rm -rf /var/run/apache2/*
  APACHE_DIR="apache2"

  exec {{ .Values.conf.software.apache2.binary }} {{ .Values.conf.software.apache2.start_parameters }}
}

function stop () {
  {{ .Values.conf.software.apache2.binary }} -k graceful-stop
}

if [ -f /etc/apache2/envvars ]; then
   # Loading Apache2 ENV variables
   source /etc/apache2/envvars
   # The directory below has to be created due to the fact that
   # libapache2-mod-wsgi-py3 doesn't create it in contrary by libapache2-mod-wsgi
   if [ ! -d ${APACHE_RUN_DIR} ]; then
      mkdir -p ${APACHE_RUN_DIR}
   fi
fi

{{- if hasKey .Values.conf.horizon.local_settings "custom_themes" }}
  # Compress Horizon's assets.
  /tmp/manage.py collectstatic --noinput
  /tmp/manage.py compress --force
  rm -rf /tmp/_tmp_.secret_key_store.lock /tmp/.secret_key_store
{{- end }}

$COMMAND
