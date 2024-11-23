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
  Returns lvm.conf formatted output from yaml input
values: |
  conf:
    lvm:
      activation: # Keys at this level are used for section headings
        udev_sync: 0
usage: |
  {{ include "helm-toolkit.utils.to_lvm_conf" .Values.conf.lvm }}
return: |
  activation {
    udev_sync = 0
  }
*/}}

{{- define "helm-toolkit.utils.to_lvm_conf" -}}
{{- range $section, $values := . -}}
{{ $section }} {{ "{" -}}
{{ range $key, $value := $values -}}
{{ if kindIs "slice" $value }}
  {{ $key }} = {{ toJson $value }}
{{- else }}
  {{ $key }} = {{ $value }}
{{- end }}
{{- end }}
{{ "}" }}
{{ end -}}
{{- end -}}
