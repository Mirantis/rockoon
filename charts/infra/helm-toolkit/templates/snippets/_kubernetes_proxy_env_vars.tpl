{{/*
abstract: |
  Renders proxy environment variables for a Kubernetes container.
examples:
  - values: |
      network:
        proxy:
          enbled: true
          env_vars:
            HTTP_PROXY: http://127.0.0.1
            HTTPS_PROXY: https://127.0.0.1
            NO_PROXY:
              - ".openstack.svc.cluster.local"
              - ".openstack.svc.cluster.public"
    usage: |
      {{ dict "envAll" $envAll "initEnvVars" true | include "helm-toolkit.snippets.kubernetes_proxy_env_vars" }}
    return: |
      env:
      - name: HTTP_PROXY
        value: http://127.0.0.1
      - name: HTTPS_PROXY
        value: https://127.0.0.1
      - name: NO_PROXY
        value: ".openstack.svc.cluster.local,.openstack.svc.cluster.public"
  - values: |
      network:
        proxy:
          enbled: true
          env_vars:
            HTTP_PROXY: http://127.0.0.1
            HTTPS_PROXY: https://127.0.0.1
            NO_PROXY:
              - ".openstack.svc.cluster.local"
              - ".openstack.svc.cluster.public"
    usage: |
      {{ dict "envAll" $envAll "initEnvVars" false | include "helm-toolkit.snippets.kubernetes_proxy_env_vars" }}
    return: |
      - name: HTTP_PROXY
        value: http://127.0.0.1
      - name: HTTPS_PROXY
        value: https://127.0.0.1
      - name: NO_PROXY
        value: ".openstack.svc.cluster.local,.openstack.svc.cluster.public"
*/}}

{{- define "helm-toolkit.snippets.kubernetes_proxy_env_vars" -}}
{{- $envAll := index . "envAll" }}
{{- $initEnvVars := index . "initEnvVars" }}
{{- if hasKey $envAll.Values.network "proxy" }}
{{- if $envAll.Values.network.proxy.enabled }}
{{- if $initEnvVars }}
env:
{{- end }}
{{ include "helm-toolkit.utils.to_k8s_env_vars" $envAll.Values.network.proxy.env_vars }}
{{- end -}}
{{- end -}}
{{- end -}}
