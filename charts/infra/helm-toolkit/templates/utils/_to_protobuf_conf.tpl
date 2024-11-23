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
  Returns protobuf formatted output from yaml input
values: |
  conf:
    cloudprober:
      surfacer:
        __type__: array
        prometheus:
          type: <<PROMETHEUS>>
          prometheus_surfacer:
            metrics_prefix: "cloudprober_"
      probe:
        __type__: array
        probe1:
          name: "openstack-instances-icmp-probe"
          type: <<PING>>
          targets:
            file_targets:
              file_path: "/etc/cloudprober/targets.d/openstack_instances.json"
              re_eval_sec: 300
        probe_r:
          name: "openstack-routers-icmp-probe"
          type: <<PING>>
          targets:
            file_targets:
              file_path: "/etc/cloudprober/targets.d/openstack_routers.json"
              re_eval_sec: 800
        probe_lb:
          __enabled__: false
          name: "openstack-loadbalancers-icmp-probe"
          type: <<PING>>
          targets:
            file_targets:
              file_path: "/etc/cloudprober/targets.d/openstack_loadbalancers.json"
              re_eval_sec: 80

usage: |
  {{ include "helm-toolkit.utils.to_protobuf_conf" .Values.conf.cloudprober }}
return: |
    probe {
        name: "openstack-instances-icmp-probe"
        targets {
            file_targets {
                file_path: "/etc/cloudprober/targets.d/openstack_instances.json"
                re_eval_sec: 300
            }
        }
        type: PING
    }
    probe {
        name: "openstack-routers-icmp-probe"
        targets {
            file_targets {
                file_path: "/etc/cloudprober/targets.d/openstack_routers.json"
                re_eval_sec: 800
            }
        }
        type: PING
    }
    surfacer {
        prometheus_surfacer {
            metrics_prefix: "cloudprober_"
        }
        type: PROMETHEUS
    }
*/}}
{{- define "helm-toolkit.utils.to_protobuf_conf" -}}
{{- $ENABLED := "__enabled__" -}}
{{- $TYPE := "__type__" -}}
{{- range $opt, $value := . -}}
  {{- if not (has $opt (list $ENABLED $TYPE)) -}}
  {{- if kindIs "map" $value -}}
    {{- if (dig $ENABLED true $value) }}
      {{- $_type := index $value $TYPE | default "dict" -}}
      {{- if eq $_type "array" -}}
        {{/* inside array type only service opts or maps are allowed, other
        opts are ignored */}}
        {{- range $k, $v := $value -}}
          {{- if kindIs "map" $v -}}
{{- include "helm-toolkit.utils.to_protobuf_conf" (dict $opt $v) -}}
          {{- end -}}
        {{- end -}}
      {{- else if eq $_type "dict" }}
{{ $opt }} {
{{- include "helm-toolkit.utils.to_protobuf_conf" $value | indent 4 }}
}
      {{- end -}}
    {{- end -}}
  {{- else -}}
    {{/* there is a special type in protobuf - enum,
         enum strings should passed as <<VAL>> from values */}}
    {{- if kindIs "string" $value -}}
      {{- if (regexMatch "^<<[A-Z]+>>$" $value) -}}
        {{- $value = trimSuffix ">>" (trimPrefix "<<" $value) -}}
      {{- else -}}
        {{- $value = $value | quote -}}
      {{- end }}
    {{- end }}
{{ $opt }}: {{ $value }}
  {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}

