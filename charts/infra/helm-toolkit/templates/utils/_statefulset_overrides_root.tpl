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

The helm-toolkit.utils.statefulset_overrides function have some limitations:

 * it doesn't allow to override values for statefulsets passed via statefulset definition.

This implementation is intended to handle those limitations:

 * it creates <service>-bin per statefulset override
 * it creates <service>-etc per statefulset override
 * it allows to override values when rendering statefulsets

 It picks data from the following structure:

  .Values:
    overrides:
      chart_service_sts:
        my_backend_name:
          values:
            labels:
              volume:
                node_selector_key: label_name
                node_selector_value: label_value
            conf:
              cinder:
                my_backend:
                  foo: bar

usage: |
  {{- list "volume" "cinder.volume.statefulset" "cinder-volume-sts" "cinder.configmap.etc" "cinder-etc" "cinder.configmap.bin" "cinder-bin" . | include "helm-toolkit.utils.statefulset_overrides_root" }}
return: |
  - configmap cinder-volume-sts-my_backend_name-etc
  - configmap cinder-volume-sts-my_backend_name-bin
  - statefulset cinder-volume-my_backend_name
*/}}

{{- define "helm-toolkit.utils.statefulset_overrides_root" }}
  {{- $statefulset := index . 0 }}
  {{- $statefulsetTemplateName := index . 1 }}
  {{ $serviceAccountName := index . 2 }}
  {{- $configmap_include := index . 3 }}
  {{- $configmap_name := index . 4 }}
  {{- $configbin_include := index . 5 }}
  {{- $configbin_name := index . 6 }}
  {{- $start_context := index . 7 }}

  {{- $context := $start_context | deepCopy }}
  {{- $_ := unset $context ".Files" }}
  {{- $statefulset_root_name := printf (print $context.Chart.Name "_" $statefulset "_sts") }}
  {{- $_ := set $context.Values "__overrides" dict }}
  {{- $_ := set $context.Values.__overrides "statefulset_list" list }}

  {{- if hasKey $context.Values "overrides" }}
    {{- range $key, $val := $context.Values.overrides }}
      {{- if eq $key $statefulset_root_name }}
        {{- range $sts_name, $sts_data := . }}
          {{- if hasKey $sts_data "values" }}
            {{- $root_copy := omit (omit ($context.Values | toYaml | fromYaml) "overrides") "__overrides" }}
            {{- $merged_dict := mergeOverwrite $root_copy $sts_data.values }}
            {{- $merged_values := dict "Values" $merged_dict }}
            {{- $list_aggregate := append $context.Values.__overrides.statefulset_list (dict "name" $sts_name "nodeData" $merged_values) }}
            {{- $_ := set $context.Values.__overrides "statefulset_list" $list_aggregate }}
          {{- end }}
        {{- end }}
      {{- end }}
    {{- end }}
  {{- end }}


  {{- range $current_dict := $context.Values.__overrides.statefulset_list }}

    {{- $context_novalues := omit $context "Values" }}
    {{- $merged_dict := mergeOverwrite $context_novalues $current_dict.nodeData }}
    {{- $_ := set $current_dict "nodeData" $merged_dict }}
    {{- $backends := index $merged_dict.Values.conf $context.Chart.Name }}
    {{- $sts_name := printf "%s-%s-%s" $context.Chart.Name $statefulset $current_dict.name | replace "_" "-" }}
    {{- $statefulset_yaml := list $sts_name "backends.conf" $serviceAccountName $merged_dict $backends | include $statefulsetTemplateName | toString | fromYaml }}
    {{- $_ := set $context.Values.__overrides "statefulset_yaml" ($statefulset_yaml | toYaml | fromYaml) }}

    {{- $name_format := (printf "%s-%s" $statefulset_root_name $current_dict.name) | replace "_" "-" }}
    {{- $_ := set $current_dict "dns_1123_name" $name_format }}

    {{/* cross-reference configmap name to container volume definitions */}}
    {{- $_ := set $context.Values.__overrides "volume_list" list }}
    {{- range $current_volume := $context.Values.__overrides.statefulset_yaml.spec.template.spec.volumes }}
      {{- $_ := set $context.Values.__overrides "volume" $current_volume }}
      {{- if hasKey $context.Values.__overrides.volume "secret" }}
        {{- if eq $context.Values.__overrides.volume.secret.secretName $configmap_name }}
          {{- $_ := set $context.Values.__overrides.volume.secret "secretName" (printf "%s-etc" $current_dict.dns_1123_name) }}
        {{- end }}
      {{- end }}
      {{- if hasKey $context.Values.__overrides.volume "configMap" }}
        {{- if eq $context.Values.__overrides.volume.configMap.name $configbin_name }}
          {{- $_ := set $context.Values.__overrides.volume.configMap "name" (printf "%s-bin" $current_dict.dns_1123_name) }}
        {{- end }}
      {{- end }}
      {{- $updated_list := append $context.Values.__overrides.volume_list $context.Values.__overrides.volume }}
      {{- $_ := set $context.Values.__overrides "volume_list" $updated_list }}
    {{- end }}
    {{- $_ := set $context.Values.__overrides.statefulset_yaml.spec.template.spec "volumes" $context.Values.__overrides.volume_list }}


    {{/* input value hash for current set of values overrides */}}
    {{- if not $context.Values.__overrides.statefulset_yaml.spec }}{{- $_ := set $context.Values.__overrides.statefulset_yaml "spec" dict }}{{- end }}
    {{- if not $context.Values.__overrides.statefulset_yaml.spec.template }}{{- $_ := set $context.Values.__overrides.statefulset_yaml.spec "template" dict }}{{- end }}
    {{- if not $context.Values.__overrides.statefulset_yaml.spec.template.metadata }}{{- $_ := set $context.Values.__overrides.statefulset_yaml.spec.template "metadata" dict }}{{- end }}
    {{- if not $context.Values.__overrides.statefulset_yaml.spec.template.metadata.annotations }}{{- $_ := set $context.Values.__overrides.statefulset_yaml.spec.template.metadata "annotations" dict }}{{- end }}
    {{- $cmap := list (printf "%s-etc" $current_dict.dns_1123_name) $current_dict.nodeData | include $configmap_include }}
    {{- $cmap_bin := list (printf "%s-bin" $current_dict.dns_1123_name) $current_dict.nodeData | include $configbin_include }}
    {{- $values_cmap_hash := $cmap | quote | sha256sum }}
    {{- $values_cmap_bin_hash := $cmap_bin | quote | sha256sum }}
    {{- $_ := set $context.Values.__overrides.statefulset_yaml.spec.template.metadata.annotations "configmap-etc-hash" $values_cmap_hash }}
    {{- $_ := set $context.Values.__overrides.statefulset_yaml.spec.template.metadata.annotations "configmap-bin-hash" $values_cmap_bin_hash }}

{{/* generate <service>-etc yaml */}}
---
{{ $cmap }}
    {{/* generate <service>-bin yaml */}}
---
{{ $cmap_bin }}
    {{/* generate statefulset yaml */}}
---
{{ $context.Values.__overrides.statefulset_yaml | toYaml }}
  {{- end }}
{{- end }}
