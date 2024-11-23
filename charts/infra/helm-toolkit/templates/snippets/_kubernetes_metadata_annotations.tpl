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
  Returns a list of annotations
values: |
  network:
    serviceExample:
      annotations:
        foo: bar
usage: |
  metadata:
    annotations:
  {{ tuple . "serviceExample" | include "helm-toolkit.snippets.kubernetes_metadata_annotations" | indent 4 }}
return: |
  metadata:
    annotations:
      foo: bar
*/}}

{{- define "helm-toolkit.snippets.kubernetes_metadata_annotations" -}}
{{- $envAll := index . 0 -}}
{{- $service := index . 1 -}}
{{- $annotations_list := index $envAll.Values.network $service "annotations" -}}
{{- if $annotations_list }}
{{- toYaml $annotations_list }}
{{- end -}}
{{- end -}}
