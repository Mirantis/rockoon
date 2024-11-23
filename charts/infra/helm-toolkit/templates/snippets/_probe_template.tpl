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
  Resolves curl or httpGet template for kubernetes probes.
values: |

usage: |
{{ dict "probe_type" "curl" "scheme" "HTTP" "host" "localhost" "path" "/" "port" (tuple "load_balancer" "internal" "api" . | include "helm-toolkit.endpoints.endpoint_port_lookup") | include "helm-toolkit.snippets.probe_template" }}

or
{{ dict "probe_type" "httpGet" "httpHeaders" (dict "Accept" "application/json" "User-Agent" "MyUserAgent") "port" (tuple "load_balancer" "internal" "api" . | include "helm-toolkit.endpoints.endpoint_port_lookup") | include "helm-toolkit.snippets.probe_template" }}

return: |
exec:
  command:
    - curl
    - --fail
    - http://localhost:9876/

or
httpGet:
  httpHeaders:
  - name: Accept
    value: application/json
  - name: User-Agent
    value: MyUserAgent
  path: /
  port: 9876
  scheme: http

*/}}

{{- define "helm-toolkit.snippets.probe_template" -}}
{{- $probe_type := index . "probe_type" -}}
{{- $scheme := index . "scheme" -}}
{{- $host := index . "host" -}}
{{- $port := index . "port" -}}
{{- $_ := required "You need to specify a port for probe endpoint" $port }}
{{- $path := index . "path" -}}
{{- $httpHeaders := index . "httpHeaders" -}}
{{- if eq $probe_type "curl" }}
exec:
  command:
    - curl
    - --fail
{{- if $httpHeaders }}
{{- range $httpHeader_name, $httpHeader_value := $httpHeaders }}
    - --header "{{- $httpHeader_name -}}:{{- $httpHeader_value -}}"
{{- end }}
{{- end }}
    - {{ lower $scheme | default "http" }}://{{ $host | default "localhost" }}:{{ $port }}{{ $path }}
{{- end }}
{{- if eq $probe_type "httpGet" }}
httpGet:
{{- if $host }}
  host: {{ $host }}
{{- end }}
  scheme: {{ $scheme | default "http" }}
  path: {{ $path | default "/" }}
  port: {{ $port }}
{{- if $httpHeaders }}
  httpHeaders:
{{ range $httpHeader_name, $httpHeader_value := $httpHeaders  }}
    - name: {{ $httpHeader_name }}
      value: {{ $httpHeader_value }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
