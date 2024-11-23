#!/bin/bash

{{/*
Copyright 2022 Mirantis Inc.

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

  {{- /* Create default share type */}}
  {{- range $name, $properties := .Values.bootstrap.share_types }}
openstack share type show {{ $name }} || \
  openstack share type create {{ $name }} \
    {{ or $properties.driver_handles_share_servers "True" }}
  {{- end }}

{{- /* Check share type and properties were added */}}
openstack share type list

{{- end }}

exit 0
