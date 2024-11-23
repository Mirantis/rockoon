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
  Renders kubernetes anti affinity rules, this function supports both hard
  'requiredDuringSchedulingIgnoredDuringExecution' and soft
  'preferredDuringSchedulingIgnoredDuringExecution' types.
values: |
  pod:
    affinity:
      anti:
        topologyKey:
          default: kubernetes.io/hostname
        type:
          default: requiredDuringSchedulingIgnoredDuringExecution
        weight:
          default: 10
usage: |
  {{ tuple . "appliction_x" "component_y" | include "helm-toolkit.snippets.kubernetes_pod_anti_affinity" }}
return: |
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
          - key: release_group
            operator: In
            values:
            - RELEASE-NAME
          - key: application
            operator: In
            values:
            - appliction_x
          - key: component
            operator: In
            values:
            - component_y
          topologyKey: kubernetes.io/hostname
*/}}

{{- define "helm-toolkit.snippets.kubernetes_pod_anti_affinity" -}}
{{- $envAll := index . 0 -}}
{{- $application := index . 1 -}}
{{- $component := index . 2 }}
{{ dict "envAll" $envAll "application" $application "component" $component | include "helm-toolkit.snippets.kubernetes_pod_anti_affinity_bundle" }}
{{- end -}}
