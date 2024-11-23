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
export HOME=/tmp

{{- if .Values.bootstrap.enabled | default "echo 'Not Enabled'" }}

  {{- /* Create volumes defined in Values.bootstrap */}}
  {{- range $name, $properties := .Values.bootstrap.volume_types }}
    {{- if $properties.volume_backend_name }}
openstack volume type show {{ $name }} || \
  openstack volume type create \
    --public \
      {{- if $properties.arguments }}
        {{- range $key, $value := $properties.arguments }}
    --{{ $key }}={{ $value }} \
        {{- end }}
      {{- end }}
      {{- range $key, $value := $properties }}
        {{- if not (eq $key "arguments") }}
    --property {{ $key }}={{ $value }} \
        {{- end }}
      {{- end }}
    {{ $name }}
    {{- end }}
  {{- end }}

  {{- /* Create volumes defined in Values.conf.backends */}}
  {{- if .Values.bootstrap.bootstrap_conf_backends }}
    {{- range $name, $properties := .Values.conf.backends }}
      {{- if $properties }}
openstack volume type show {{ $name }} || \
  openstack volume type create \
    --public \
    --property volume_backend_name={{ $properties.volume_backend_name }} \
    {{ $name }}
      {{- end }}
    {{- end }}
  {{- end }}

  {{- /* Create volumes defined in Values.conf.standalone_backends */}}
  {{- if .Values.bootstrap.bootstrap_conf_backends }}
    {{- if .Values.conf.standalone_backends }}
      {{- if hasKey .Values.conf.standalone_backends "statefulsets" }}
        {{- range $name, $standalone_backend := .Values.conf.standalone_backends.statefulsets }}
          {{- if (hasKey $standalone_backend "backend_conf") }}
            {{- if (hasKey $standalone_backend.backend_conf "volume_backend_name") }}
openstack volume type show {{ $name }} || \
  openstack volume type create \
    --public \
    --property volume_backend_name={{ $standalone_backend.backend_conf.volume_backend_name }} {{ $name }}
            {{- end }}
          {{- end }}
        {{- end }}
      {{- end }}
    {{- end }}
  {{- end }}

{{- /* Check volume type and properties were added */}}
openstack volume type list --long

# Set volumes quote to unlim for cinder service project to have a chance to create
# volumes, images etc inside it.
SERVICE_DOMAIN_ID=$(openstack --os-cloud admin-system domain show {{ .Values.endpoints.identity.auth.cinder.project_domain_name }} -f value -c id)
SERVICE_PROJECT_ID=$(openstack --os-cloud admin-system project show {{ .Values.endpoints.identity.auth.cinder.project_name }} --domain ${SERVICE_DOMAIN_ID} -f value -c id)

# NOTE(vsaienko): unless is fixed PRODX-23599 in Yogga release, command: openstack --os-cloud admin quota set --volumes -1 507d9f0509524609bff4c0159432739a doesn't work.
VOLUME_V3_ENDPOINT=$(openstack --os-cloud admin catalog show volumev3 |grep internal | awk '{print $4}')
if [[ -n $VOLUME_V3_ENDPOINT ]]; then
    TOKEN=$(openstack token issue -f value -c id)
    curl -X PUT ${VOLUME_V3_ENDPOINT}/os-quota-sets/${SERVICE_PROJECT_ID} -H "Accept: application/json" -H "Content-Type: application/json" -H "X-Auth-Token: $TOKEN" -d '{"quota_set": {"tenant_id": "'${SERVICE_PROJECT_ID}'", "volumes": -1}}'
fi

{{- end }}

exit 0
