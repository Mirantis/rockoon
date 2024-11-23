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
  Returns ipsec.conf formatted output from yaml input
values: |
  conf:
    ipsec:
      config setup:
        uniqueids: yes

usage: |
  {{ include "strongswan.utils.to_ipsec_conf" .Values.conf.ipsec }}
return: |
  config setup
      uniqueids=yes
*/}}

{{- define "strongswan.utils.to_ipsec_conf" -}}
{{- range $section, $values := . }}
{{ $section }}
{{ range $key, $value := $values -}}
{{ printf "  %s=%s" $key $value }}
{{ end }}
{{- end -}}
{{- end -}}
