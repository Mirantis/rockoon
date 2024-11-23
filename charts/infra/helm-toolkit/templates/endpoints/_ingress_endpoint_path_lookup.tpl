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
  Resolves the path for an endpoint
values: |
  endpoints:
    cluster_domain_suffix: cluster.local
    identity:
      path:
       ingress:
         default: /dbname
      port:
        ks-pub:
          default: 3306
usage: |
  {{ tuple "identity" "internal" "ks-pub" . | include "helm-toolkit.endpoints.ingress_endpoint_path_lookup" }}
return: |
  /dbname
*/}}

{{- define "helm-toolkit.endpoints.ingress_endpoint_path_lookup" -}}
{{- $type := index . 0 -}}
{{- $endpoint := index . 1 -}}
{{- $port := index . 2 -}}
{{- $context := index . 3 -}}
{{- $endpointMap := index $context.Values.endpoints ( $type | replace "-" "_" ) }}
{{- if kindIs "map" $endpointMap.path }}
{{- if index $endpointMap.path "ingress" }}
{{- $ingressPath := index $endpointMap.path.ingress $endpoint | default $endpointMap.path.ingress.default | default "/" }}
{{- printf "%s" $ingressPath }}
{{- else }}
{{- printf "/" }}
{{- end }}
{{- else }}
{{- printf "/" }}
{{- end }}
{{- end }}
