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
  Returns key value pair in INI format (key = value), accounting
  for Python variable declaration.
values: |
  conf:
    gunicorn:
      config:
        log_level: 3
        bool_val: false
        dict_val:
          key1: val1
          key2: 2
          3: val2
        list_val:
          - e1
          - 33
usage: |
  {{ include "helm-toolkit.utils.to_kv_list" .Values.conf.gunicorn.config }}
return: |
  log_level = 3
  bool_val = False
  dict_vale = {"key1": "val1", "key2": 2, 3: "val2"}
  list_val = ["e1", 33]
*/}}

{{- define "helm-toolkit.utils.to_kv_py_list._formatList" -}}
{{-   $first := true }}
{{-   range $i := . -}}
{{-     if not $first }}, {{ end -}}
{{-     include "helm-toolkit.utils.to_kv_py_list._formatValue" $i }}
{{-     $first = false -}}
{{-   end }}
{{- end }}

{{- define "helm-toolkit.utils.to_kv_py_list._formatMap" }}
{{-   $first := true }}
{{-   range $k, $v := . -}}
{{-     if not $first }}, {{ end -}}
{{-     if or (kindIs "int64" $k) (kindIs "float64" $k) -}}{{ $k }}{{- else -}}{{ $k | quote }}{{-  end -}}: {{ include "helm-toolkit.utils.to_kv_py_list._formatValue" $v}}
{{-     $first = false -}}
{{-   end }}
{{- end }}

{{- define "helm-toolkit.utils.to_kv_py_list._formatValue" -}}
{{-   $value := . -}}
{{-   if kindIs "string" $value }}
{{-     $value | quote }}
{{-   else if kindIs "bool" $value }}
{{-     title ($value | toString ) }}
{{-   else if kindIs "slice" $value -}}
[{{     include "helm-toolkit.utils.to_kv_py_list._formatList" $value }}]
{{-   else if kindIs "map" $value -}}
{ {{-     include "helm-toolkit.utils.to_kv_py_list._formatMap" $value -}} }
{{-   else }}
{{-     $value }}
{{-   end -}}
{{- end -}}

{{- define "helm-toolkit.utils.to_kv_py_list" -}}
{{-   range $key, $value :=  . }}
{{ $key }} = {{ include "helm-toolkit.utils.to_kv_py_list._formatValue" $value }}
{{-   end }}
{{- end -}}
