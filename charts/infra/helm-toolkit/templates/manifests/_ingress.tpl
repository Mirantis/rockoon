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
  Creates a manifest for a services ingress rules.
examples:
  - values: |
      network:
        api:
          ingress:
            public: true
            classes:
              namespace: "nginx"
              cluster: "nginx-cluster"
            annotations:
              nginx.ingress.kubernetes.io/rewrite-target: /
      secrets:
        tls:
          key_manager:
            api:
              public: barbican-tls-public
      endpoints:
        cluster_domain_suffix: cluster.local
        key_manager:
          name: barbican
          hosts:
            default: barbican-api
            public: barbican
          host_fqdn_override:
            default: null
            public:
              host: barbican.openstackhelm.example
              tls:
                crt: |
                  FOO-CRT
                key: |
                  FOO-KEY
                ca: |
                  FOO-CA_CRT
          path:
            default: /
          scheme:
            default: http
            public: https
          port:
            api:
              default: 9311
              public: 80
    usage: |
      {{- include "helm-toolkit.manifests.ingress" ( dict "envAll" . "backendServiceType" "key-manager" "backendPort" "b-api" "endpoint" "public" ) -}}
    return: |
      ---
      apiVersion: networking.k8s.io/v1
      kind: Ingress
      metadata:
        name: barbican-namespace-fqdn
        annotations:
          kubernetes.io/ingress.class: "nginx"
          nginx.ingress.kubernetes.io/rewrite-target: /

      spec:
        tls:
          - secretName: barbican-tls-public
            hosts:
              - barbican.openstackhelm.example
        rules:
          - host: barbican.openstackhelm.example
            http:
              paths:
                - path: /
                  pathType: ImplementationSpecific
                  backend:
                    service:
                      name: barbican-api
                      port:
                        name: b-api
*/}}

{{- define "helm-toolkit.manifests.ingress._host_rules" -}}
{{- $vHost := index . "vHost" -}}
{{- $backendName := index . "backendName" -}}
{{- $backendPort := index . "backendPort" -}}
{{- $endpointPath := index . "endpointPath" | default "/" -}}
- host: {{ $vHost }}
  http:
    paths:
      - path: /
        pathType: ImplementationSpecific
        backend:
          service:
            name: {{ $backendName }}
            port:
{{- if or (kindIs "int" $backendPort) (regexMatch "^[0-9]{1,5}$" $backendPort) }}
              number: {{ $backendPort | int }}
{{- else }}
              name: {{ $backendPort | quote }}
{{- end }}
{{- end }}

{{- define "helm-toolkit.manifests.ingress" -}}
{{- $envAll := index . "envAll" -}}
{{- $backendService := index . "backendService" | default "api" -}}
{{- $backendServiceType := index . "backendServiceType" -}}
{{- $backendPort := index . "backendPort" -}}
{{- $endpoint := index . "endpoint" | default "public" -}}
{{- $certIssuer := index . "certIssuer" | default "" -}}
{{- $ingressName := tuple $backendServiceType $endpoint $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup" }}
{{- $backendName := tuple $backendServiceType "internal" $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup" }}
{{- $hostNameFull := tuple $backendServiceType $endpoint $envAll | include "helm-toolkit.endpoints.hostname_fqdn_endpoint_lookup" }}
{{- $endpointPath := tuple $backendServiceType $endpoint $backendService $envAll | include "helm-toolkit.endpoints.ingress_endpoint_path_lookup" }}
{{- if not ( hasSuffix ( printf ".%s.svc.%s" $envAll.Release.Namespace $envAll.Values.endpoints.cluster_domain_suffix) $hostNameFull) }}
{{- $ingressController := "namespace" }}
{{- $hostNameFullRules := dict "vHost" $hostNameFull "backendName" $backendName "backendPort" $backendPort "endpointPath" $endpointPath }}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ printf "%s-%s-%s" $ingressName $ingressController "fqdn" }}
  annotations:
    kubernetes.io/ingress.class: {{ index $envAll.Values.network $backendService "ingress" "classes" $ingressController | quote }}
{{- $host := index $envAll.Values.endpoints ( $backendServiceType | replace "-" "_" ) "host_fqdn_override" }}
    nginx.ingress.kubernetes.io/configuration-snippet: '#ca secret hash: {{ $host | include "helm-toolkit.utils.get_hash" }}'
{{ toYaml (index $envAll.Values.network $backendService "ingress" "annotations") | indent 4 }}
spec:
{{- if hasKey $host $endpoint }}
{{- $endpointHost := index $host $endpoint }}
{{- if kindIs "map" $endpointHost }}
{{- if hasKey $endpointHost "tls" }}
{{- if and ( not ( empty $endpointHost.tls.key ) ) ( not ( empty $endpointHost.tls.crt ) ) }}
{{- $secretName := index $envAll.Values.secrets "tls" ( $backendServiceType | replace "-" "_" ) $backendService $endpoint }}
{{- $_ := required "You need to specify a secret in your values for the endpoint" $secretName }}
  tls:
    - secretName: {{ $secretName }}
      hosts:
        - {{ index $hostNameFullRules "vHost" }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
  rules:
{{ $hostNameFullRules | include "helm-toolkit.manifests.ingress._host_rules" | indent 4 }}
{{- end }}
{{- end }}
