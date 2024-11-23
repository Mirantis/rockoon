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

{{- define "cinder.utils.is_tgt_used" -}}
{{- $env := index . -}}
{{- $result := true -}}
{{- $continue := true -}}
{{- $ds_conf := $env.standalone_backends.daemonset.conf -}}
{{- if(and $ds_conf (kindIs "map" $ds_conf)) -}}
{{-   range $name, $values := $ds_conf -}}
{{-     if (and $continue (ne $name "DEFAULT")) -}}
{{-       if (hasKey $values "target_helper") -}}
{{-         $result = eq $values.target_helper "tgtadm" -}}
{{-         $continue = false -}}
{{-       end -}}
{{-     end -}}
{{-   end }}
{{-   if (and $continue (hasKey $ds_conf.DEFAULT "target_helper")) -}}
{{-     $result = eq $ds_conf.DEFAULT.target_helper "tgtadm" -}}
{{-     $continue = false -}}
{{-   end -}}
{{- end -}}
{{- if(and $continue (hasKey $env.cinder.DEFAULT "target_helper")) -}}
{{-   $result = eq $env.cinder.DEFAULT.target_helper "tgtadm" -}}
{{- end -}}
{{- $result }}
{{- end -}}
