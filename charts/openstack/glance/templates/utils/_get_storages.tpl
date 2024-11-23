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

{{- define "glance.utils.get_storages" -}}
{{- $envAll := index . 0 -}}
{{- $result := list -}}
{{- if $envAll.Values.conf.glance.glance_store.stores -}}
  {{- $param := $envAll.Values.conf.glance.glance_store.stores -}}
  {{- if kindIs "slice" $param -}}
    {{- $result = concat $result $param -}}
  {{- else -}}
    {{- range $name := splitList "," $param }}
      {{- $result = append $result $name -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- if $envAll.Values.conf.glance.DEFAULT.enabled_backends -}}
  {{- $param := $envAll.Values.conf.glance.DEFAULT.enabled_backends -}}
  {{- if kindIs "slice" $param -}}
    {{- range $name := $param }}
      {{- $result = append $result ( split ":" $name )._1 -}}
    {{- end -}}
  {{- else -}}
    {{- range $name := splitList "," $param }}
      {{- $result = append $result ( split ":" $name )._1 -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- $result | uniq | toJson -}}
{{- end -}}
