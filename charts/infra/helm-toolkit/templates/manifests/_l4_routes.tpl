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
  Creates a manifest for Gateway API l4 route for service.
examples:
  - values: |
      network:
        powerdns:
          tcp_route:
            gatewayName: test1
          udp_route:
            gatewayName: test2
      endpoints:
        cluster_domain_suffix: cluster.local
        powerdns:
          auth:
            service:
              token: chiave_segreta
          hosts:
            default: designate-powerdns
          host_fqdn_override:
            default: null
          port:
            powerdns_api:
              default: 8081
            powerdns_tcp:
              default: 53
            powerdns:
              default: 53
              protocol: UDP
    usage: |
      {{- $tcpRouteOpts := dict "envAll" $envAll "backendServiceType" "powerdns" "backendService" "powerdns" "backendPort" 53 -}}
      {{ $tcpRouteOpts | include "helm-toolkit.manifests.tcp_route" }}
      {{- $udpRouteOpts := dict "envAll" $envAll "backendServiceType" "powerdns" "backendService" "powerdns" "backendPort" 53 -}}
      {{ $udpRouteOpts | include "helm-toolkit.manifests.udp_route" }}
    return: |
      ---
      apiVersion: gateway.networking.k8s.io/v1
      kind: TCPRoute
      metadata:
        name: designate-powerdns-svc
      spec:
        parentRefs:
        - group: gateway.networking.k8s.io
          kind: Gateway
          name: test1
        rules:
          - backendRefs:
            - group: ""
              kind: Service
              name: designate-powerdns
              port: 53
              weight: 1
      ---
      apiVersion: gateway.networking.k8s.io/v1
      kind: UDPRoute
      metadata:
        name: designate-powerdns-svc
      spec:
        parentRefs:
        - group: gateway.networking.k8s.io
          kind: Gateway
          name: test2
        rules:
          - backendRefs:
            - group: ""
              kind: Service
              name: designate-powerdns
              port: 53
              weight: 1
*/}}

{{- define "helm-toolkit.manifests.l4_routes._rules" -}}
{{- $backendName := index . "backendName" -}}
{{- $backendPort := index . "backendPort" -}}
- backendRefs:
  - group: ""
    kind: Service
    name: {{ $backendName }}
    port: {{ $backendPort }}
    weight: 1
{{- end }}

{{- define "helm-toolkit.manifests._l4_route" -}}
{{- $envAll := index . "envAll" -}}
{{- $route_type := index . "routeType" | default "tcp" }}
{{- $kind := printf "%sRoute" (upper $route_type) }}
{{- $backendService := index . "backendService" | default "api" -}}
{{- $backendServiceType := index . "backendServiceType" -}}
{{- $l4RouteConf := index $envAll.Values.network $backendService (printf "%s_route" $route_type) | default dict -}}
{{- $endpoint := index . "endpoint" | default "public" -}}
{{- $backendPort := required (printf "%s route backend port not specified" $route_type) .backendPort -}}
{{- $backendName := tuple $backendServiceType "internal" $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup" }}
{{- $gatewayName := index $l4RouteConf "gatewayName" | default (tuple "app_gateway" "internal" $envAll | include "helm-toolkit.endpoints.hostname_short_endpoint_lookup") }}
{{- $svcRules := dict "backendName" $backendName "backendPort" $backendPort }}
{{- $listenerName := index $l4RouteConf "listenerName" }}
{{- $routeName := printf "%s-%s" $backendName "svc" }}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: {{ $kind }}
metadata:
  name: {{ $routeName }}
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: {{ $gatewayName }}
{{- if $listenerName }}
    sectionName: {{ $listenerName }}
{{- end }}
  rules:
{{ $svcRules | include "helm-toolkit.manifests.l4_routes._rules" | indent 4 }}
{{- end }}

{{- define "helm-toolkit.manifests.tcp_route" -}}
{{- $context := . }}
{{- $_ := set $context "routeType" "tcp" }}
{{- $context | include "helm-toolkit.manifests._l4_route"}}
{{- end }}

{{- define "helm-toolkit.manifests.udp_route" -}}
{{- $context := . }}
{{- $_ := set $context "routeType" "udp" }}
{{- $context | include "helm-toolkit.manifests._l4_route"}}
{{- end }}
