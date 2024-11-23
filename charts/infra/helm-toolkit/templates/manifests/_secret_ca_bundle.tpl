{{/*
Copyright 2019 Mirantis Inc.

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
  This manifest creates secret object with CA certificates
examples:
    usage: |
      {{ include "helm-toolkit.manifests.secret_ca_bundle" ( dict "envAll" . "secretPrefix" "horizon" ) }}
    return: |
      ---
      apiVersion: v1
      kind: Secret
      metadata:
        name: horizon-ca-bundle
      type: Opaque
      data:
        ca_bundle: base64 encoded CA cert bundle
*/}}

{{- define "helm-toolkit.manifests.secret_ca_bundle" -}}
{{- $envAll := index . "envAll" -}}
{{- $secretPrefix := index . "secretPrefix" -}}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{ $secretPrefix }}-ca-bundle
type: Opaque
data:
{{- $cabundle := "" }}
{{- $endpoint_name := index . "endpoint" | default "public" }}
{{- range $key, $val := $envAll.Values.endpoints }}
{{- if kindIs "map" ( index $envAll.Values.endpoints $key) }}
{{- $endpoint := index $envAll.Values.endpoints $key -}}
{{- if hasKey $endpoint "host_fqdn_override" }}
{{- if hasKey $endpoint.host_fqdn_override $endpoint_name }}
{{- if hasKey (index $endpoint.host_fqdn_override $endpoint_name) "tls" }}
{{- if hasKey (index $endpoint.host_fqdn_override $endpoint_name "tls") "ca" }}
{{- $ca := index $endpoint.host_fqdn_override $endpoint_name "tls" "ca" }}
{{- $cabundle = printf "%s%s" $cabundle $ca }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
  ca_bundle: {{ $cabundle | trim | b64enc}}
{{- end }}
