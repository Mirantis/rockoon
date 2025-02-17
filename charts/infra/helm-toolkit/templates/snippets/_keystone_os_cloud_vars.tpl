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

{{/*
abstract: |
  Returns a set of container enviorment variables, equivlant to an openrc for
  use with keystone based command line clients.
usage: |
  {{ include "helm-toolkit.snippets.keystone_os_cloud_vars" ( dict "osCloudName" "admin" ) }}
return: |
  - name: OS_CLOUD
    value: admin
*/}}

{{- define "helm-toolkit.snippets.keystone_os_cloud_vars" }}
{{- $osCloudName := index . "osCloudName" | default "admin" }}
{{- $osCloudNameSystem := index . "osCloudNameSystem" | default "admin-system" }}
- name: OS_CLOUD
  value: {{ $osCloudName }}
- name: OS_CLOUD_SYSTEM
  value: {{ $osCloudNameSystem }}
{{- end }}
