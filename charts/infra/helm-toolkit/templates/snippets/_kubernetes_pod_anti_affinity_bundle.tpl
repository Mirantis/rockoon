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
  {{ dict "envAll" . "label1" "foo" "label2" "bar" "label3" "buz" | include "helm-toolkit.snippets.kubernetes_pod_anti_affinity_bundle" }}
return: |
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
          - key: release_group
            operator: In
            values:
            - RELEASE-NAME
          - key: label1
            operator: In
            values:
            - foo
          - key: label2
            operator: In
            values:
            - bar
          - key: label3
            operator: In
            values:
            - buz
          topologyKey: kubernetes.io/hostname
*/}}

{{- define "helm-toolkit.snippets.kubernetes_pod_anti_affinity._match_expressions" -}}
{{-   $envAll := index . "envAll" -}}
{{-   $labels := omit . "envAll" -}}
{{-   $expressionRelease := dict "key" "release_group" "operator" "In"  "values" ( list ( $envAll.Values.release_group | default $envAll.Release.Name ) ) -}}
{{-   $result := list $expressionRelease -}}
{{-   range $label, $value := $labels }}
{{-     $temp := append $result (dict "key" $label "operator" "In"  "values" ( list $value )) }}
{{-     $result = $temp -}}
{{-   end -}}
{{-   $result | toYaml }}
{{- end -}}

{{- define "helm-toolkit.snippets.kubernetes_pod_anti_affinity_bundle" -}}
{{-   $envAll := index . "envAll" -}}
{{-   $labels := omit . "envAll" }}
{{-   $component := index $labels "component" }}
{{-   $antiAffinityType := index $envAll.Values.pod.affinity.anti.type $component | default $envAll.Values.pod.affinity.anti.type.default }}
{{-   $antiAffinityKey := index $envAll.Values.pod.affinity.anti.topologyKey $component | default $envAll.Values.pod.affinity.anti.topologyKey.default }}
{{-   $matchExpressions := include "helm-toolkit.snippets.kubernetes_pod_anti_affinity._match_expressions" . -}}
podAntiAffinity:
{{-   if eq $antiAffinityType "preferredDuringSchedulingIgnoredDuringExecution" }}
  {{ $antiAffinityType }}:
  - podAffinityTerm:
      labelSelector:
        matchExpressions:
{{ $matchExpressions | indent 10 }}
      topologyKey: {{ $antiAffinityKey }}
{{-     if  $envAll.Values.pod.affinity.anti.weight }}
    weight: {{ index $envAll.Values.pod.affinity.anti.weight $component | default $envAll.Values.pod.affinity.anti.weight.default }}
{{-     else }}
    weight: 10
{{-     end -}}
{{- else if eq $antiAffinityType "requiredDuringSchedulingIgnoredDuringExecution" }}
  {{ $antiAffinityType }}:
  - labelSelector:
      matchExpressions:
{{ $matchExpressions | indent 8 }}
    topologyKey: {{ $antiAffinityKey }}
{{-   end -}}
{{- end -}}
