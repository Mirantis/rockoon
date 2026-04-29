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
  Creates a manifest for a services Gateway API http route for fqdn.
examples:
  - values: |
      network:
        api:
          http_route:
            rule:
              timeouts:
                request: 30s
                backendRequest: 15s
              filters:
                0_host_rewrite:
                  enabled: true
                  type: "URLRewrite"
                  urlRewrite:
                    path:
                      replacePrefixMatch: /
                      type: ReplacePrefixMatch
      endpoints:
        cluster_domain_suffix: cluster.local
        app_gateway:
          hosts:
            default:
              host: app-gateway
          port:
            https:
              default: 10443
              public: 443
          host_fqdn_override:
            public: null
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
      {{- $httpRouteOpts := dict "envAll" $envAll "backendServiceType" "key_manager" "backendService" "api" "backendPort" 9311 -}}
      {{ $httpRouteOpts | include "helm-toolkit.manifests.http_route" }}
    return: |
      apiVersion: gateway.networking.k8s.io/v1
      kind: HTTPRoute
      metadata:
        name: barbican-api-fqdn
      spec:
        hostnames:
        - barbican.openstackhelm.example
        parentRefs:
        - group: gateway.networking.k8s.io
          kind: Gateway
          name: app-gateway
        rules:
          - backendRefs:
            - group: ""
              kind: Service
              name: barbican-api
              port: 9311
              weight: 1
            filters:
            - type: URLRewrite
              urlRewrite:
                path:
                  replacePrefixMatch: /
                  type: ReplacePrefixMatch
            matches:
            - path:
              type: PathPrefix
              value: /
            timeouts:
              backendRequest: 15s
              request: 30s
*/}}

{{- define "helm-toolkit.manifests.http_route._host_rules._filters" }}
{{- $list_items := list }}
{{- $filters_dict := . }}
{{- range $name := sortAlpha (keys $filters_dict) }}
  {{- $f := index $filters_dict $name }}
  {{- if dig "enabled" true $f }}
    {{- $_ := unset $f "enabled" }}
    {{- $list_items = append $list_items $f }}
  {{- end }}
{{- end }}
{{- if $list_items }}
{{ toYaml $list_items }}
{{- end }}
{{- end }}

{{- define "helm-toolkit.manifests.http_route._host_rules" -}}
{{- $backendName := index . "backendName" -}}
{{- $backendPort := index . "backendPort" -}}
{{- $endpointPath := index . "endpointPath" | default "/" -}}
{{- $ruleConf := index . "ruleConf" | default dict -}}
{{- $filters := include "helm-toolkit.manifests.http_route._host_rules._filters" (index $ruleConf "filters") }}
{{- $timeouts := index $ruleConf "timeouts" -}}
{{- $sessionPersistence := index $ruleConf "sessionPersistence" -}}
{{- $retry := index $ruleConf "retry" -}}
- backendRefs:
  - group: ""
    kind: Service
    name: {{ $backendName }}
    port: {{ $backendPort }}
    weight: 1
{{- if $filters }}
  filters:
{{- $filters | indent 2 }}
{{- end }}
  matches:
  - path:
    type: PathPrefix
    value: {{ $endpointPath }}
{{- if $retry }}
  retry:
{{ toYaml $retry | indent 4 }}
{{- end }}
{{- if $timeouts }}
  timeouts:
{{ toYaml $timeouts | indent 4 }}
{{- end }}
{{- if $sessionPersistence }}
  sessionPersistence:
{{ toYaml $sessionPersistence | indent 4 }}
{{- end }}
{{- end }}

{{- define "helm-toolkit.manifests.http_route" -}}
{{- $envAll := index . "envAll" -}}
{{- $backendService := index . "backendService" | default "api" -}}
{{- $backendServiceType := index . "backendServiceType" -}}
{{- $httpRouteConf := index $envAll.Values.network $backendService "http_route" -}}
{{- if not $httpRouteConf -}}
{{- fail (printf "%s %s http_route not found" $backendServiceType $backendService) -}}
{{- end -}}
{{- $endpoint := index . "endpoint" | default "public" -}}
{{- $backendPort := required "Http route backend port not specified" .backendPort -}}
{{- $backendName := tuple $backendServiceType "internal" $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup" }}
{{- $gatewayName := index $httpRouteConf "gatewayName" | default (tuple "app_gateway" "internal" $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup") }}
{{- $routeName := printf "%s-%s" $backendName "fqdn" }}
{{- $hostNameFull := tuple $backendServiceType $endpoint $envAll | include "helm-toolkit.endpoints.hostname_fqdn_endpoint_lookup" }}
{{- $endpointPath := tuple $backendServiceType $endpoint $backendService $envAll | include "helm-toolkit.endpoints.http_route_endpoint_path_lookup" }}
{{- $ruleConf := index $httpRouteConf "rule" }}
{{- $hostNameFullRules := dict "backendName" $backendName "backendPort" $backendPort "endpointPath" $endpointPath "ruleConf" $ruleConf }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ $routeName }}
spec:
  hostnames:
  - {{ $hostNameFull }}
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: {{ $gatewayName }}
  rules:
{{ $hostNameFullRules | include "helm-toolkit.manifests.http_route._host_rules" | indent 4 }}
{{- end }}