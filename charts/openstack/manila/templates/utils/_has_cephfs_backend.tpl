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

{{- define "manila.utils.has_cephfs_backend" -}}
  {{- $env := index . 0 -}}
  {{- $has_ceph := false -}}
  {{- range $_, $backend := $env -}}
    {{- if kindIs "map" $backend -}}
      {{- if $backend.share_driver }}
        {{- $has_ceph = or $has_ceph (eq $backend.share_driver "manila.share.drivers.cephfs.driver.CephFSDriver") -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- $has_ceph -}}
{{- end -}}
