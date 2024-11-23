#!/bin/bash

{{/*
Copyright 2019 Mirantis inc.

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

set -xe
endpt={{ tuple "identity" "internal" "api" . | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" }}
path={{ .Values.conf.keystone.identity.domain_config_dir | default "/etc/keystonedomains" }}

{{- range $k, $v := .Values.conf.ks_federations }}

mapping_filename=${path}/keystone-federations-mapping.{{ $k }}.json

{{- if and (hasKey $v "identity_provider") (hasKey $v "mapping") (hasKey $v "protocol") }}
openstack --os-cloud=${OS_CLOUD_SYSTEM} identity provider show  {{ $v.identity_provider.id }} || openstack --os-cloud=${OS_CLOUD_SYSTEM} identity provider create --remote-id {{ include "helm-toolkit.utils.joinListWithComma" $v.identity_provider.remote_ids }} --domain {{ $v.identity_provider.domain_id }} {{ $v.identity_provider.id }}
# ensure the remote-id and domain are updated
openstack --os-cloud=${OS_CLOUD_SYSTEM} identity provider set {{ $v.identity_provider.id }} --remote-id {{ include "helm-toolkit.utils.joinListWithComma" $v.identity_provider.remote_ids }}
openstack --os-cloud=${OS_CLOUD_SYSTEM} mapping show {{ $v.mapping.id }} || openstack --os-cloud=${OS_CLOUD_SYSTEM} mapping create --rules ${mapping_filename} {{ $v.mapping.id }}
{{- range $proto_name, $settings := $v.protocol }}
openstack --os-cloud=${OS_CLOUD_SYSTEM} federation protocol show --identity-provider {{ $settings.idp_id }} {{ $proto_name }} || openstack --os-cloud=${OS_CLOUD_SYSTEM} federation protocol create --identity-provider {{ $settings.idp_id }} --mapping {{ $settings.mapping_id }} {{ $proto_name }}
{{- end }}
{{- else }}
echo "identity_provider, mapping or protocol  section is not defined in .Values.conf.ks_federations.{{ $k }}"
exit 1
{{- end }}

{{- end }}
