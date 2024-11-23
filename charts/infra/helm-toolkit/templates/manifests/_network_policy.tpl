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
  Creates a network policy manifest for services.
values: |
  network_policy:
    myLabel:
      spec:
        podSelector:
          matchLabels:
            component: api
        ingress:
        - from:
          - podSelector:
              matchLabels:
                application: keystone
          ports:
          - protocol: TCP
            port: 80
        egress:
        - to:
          - namespaceSelector:
              matchLabels:
                name: default
          - namespaceSelector:
              matchLabels:
                name: kube-public
          ports:
          - protocol: TCP
            port: 53
          - protocol: UDP
            port: 53
usage: |
  {{ dict "envAll" . | include "helm-toolkit.manifests.kubernetes_network_policy" }}
return: |
  ---
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: RELEASE-NAME-myLabel
    namespace: NAMESPACE
  spec:
    policyTypes:
      - Ingress
      - Egress
    podSelector:
      matchLabels:
        application: myLabel
        component: api
    ingress:
    - from:
      - podSelector:
          matchLabels:
            application: keystone
      ports:
      - protocol: TCP
        port: 80
    egress:
      - to:
        - podSelector:
            matchLabels:
              name: default
        - namespaceSelector:
            matchLabels:
              name: kube-public
        ports:
        - protocol: TCP
          port: 53
        - protocol: UDP
          port: 53
*/}}

{{- define "helm-toolkit.manifests.kubernetes_network_policy" -}}
{{- $envAll := index . "envAll" -}}
{{- range $label, $value := $envAll.Values.network_policy }}
{{- $raw_spec := (index $value "spec") }}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ $envAll.Release.Name }}-{{ $label | replace "_" "-" }}-netpol
  namespace: {{ $envAll.Release.Namespace }}
spec:
{{ $raw_spec | toYaml | indent 2 }}
{{- end }}
{{- end }}
