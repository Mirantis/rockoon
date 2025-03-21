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
  Returns file with env variables ready to source .
  In case value is set to "<None>" the key won`t be
  reflected in config
values: |
  conf:
    keystone:
      FOO: bar
usage: |
  {{ include "helm-toolkit.utils.to_env_conf" .Values.conf.keystone }}
return: |
  export FOO=bar
*/}}

{{- define "helm-toolkit.utils.to_env_conf" -}}
{{-   range $key, $value := . -}}
{{-     if not (eq (toString $value) "<None>") -}}
{{-       if kindIs "map" $value }}
export {{ $key }}={{ $value }}
{{-       else}}
export {{ $key }}='{{ $value }}'
{{-       end }}
{{      end -}}
{{    end -}}
{{- end -}}
