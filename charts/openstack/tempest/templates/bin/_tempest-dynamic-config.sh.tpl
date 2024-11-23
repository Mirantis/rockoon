#!/bin/bash

{{/*
Copyright 2017 The Openstack-Helm Authors.

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

TEMPEST_CONF="/etc/tempest/tempest.conf"

source /tmp/functions.sh

{{- if not .Values.conf.tempest.load_balancer.test_server_path }}
lb_test_server_path=$(python -c "import pkg_resources; print(pkg_resources.resource_filename('octavia_tempest_plugin.contrib.test_server', 'test_server.bin'))" || /bin/true)
if [[ -n $lb_test_server_path ]]; then
iniset $TEMPEST_CONF load_balancer test_server_path $lb_test_server_path
fi
{{- end }}

sed -i "s/\${NODE_IP}/${NODE_IP}/g" $TEMPEST_CONF

{{- if .Values.manifests.job_static_accounts }}
iniset $TEMPEST_CONF auth test_accounts_file /tmp/static-accounts.yaml
iniset $TEMPEST_CONF auth use_dynamic_credentials False
iniset $TEMPEST_CONF auth default_credentials_domain_name {{ .Values.conf.static_accounts.domain_name }}
{{- end }}
