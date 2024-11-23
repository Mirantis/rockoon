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
  Renders a set of standardised labels
values: |
  release_group: null
usage: |
  {{ dict "envAll" . "label1" "foo" "label2" "bar" "label3" "buz" | include "helm-toolkit.snippets.kubernetes_metadata_labels_bundle" }}
return: |
  release_group: RELEASE-NAME
  label1: foo
  label2: bar
  label3: buz
*/}}

{{- define "helm-toolkit.snippets.kubernetes_metadata_labels_bundle" -}}
{{-   $envAll := index . "envAll" -}}
{{-   $labels := omit . "envAll" -}}
release_group: {{ $envAll.Values.release_group | default $envAll.Release.Name }}
{{-   range $label, $value := $labels }}
{{ $label }}: {{ $value }}
{{-   end }}
{{- end -}}
