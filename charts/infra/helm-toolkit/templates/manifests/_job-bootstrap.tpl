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

# This function creates a manifest for db creation and user management.
# It can be used in charts dict created similar to the following:
# {- $bootstrapJob := dict "envAll" . "serviceName" "senlin" -}
# { $bootstrapJob | include "helm-toolkit.manifests.job_bootstrap" }
{{/*
To enable security context define the following values:
  pod:
    security_context:
      bootstrap:
        pod:
          runAsUser: 65534
        container:
          bootstrap:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
*/}}
{{- define "helm-toolkit.manifests.job_bootstrap" -}}
{{- $envAll := index . "envAll" -}}
{{- $serviceName := index . "serviceName" -}}
{{- $nodeSelector := index . "nodeSelector" | default ( dict $envAll.Values.labels.job.node_selector_key $envAll.Values.labels.job.node_selector_value ) -}}
{{- $podVolMounts := index . "podVolMounts" | default false -}}
{{- $podVols := index . "podVols" | default false -}}
{{- $configMapBin := index . "configMapBin" | default (printf "%s-%s" $serviceName "bin" ) -}}
{{- $configMapEtc := index . "configMapEtc" | default (printf "%s-%s" $serviceName "etc" ) -}}
{{- $configFile := index . "configFile" | default (printf "/etc/%s/%s.conf" $serviceName $serviceName ) -}}
{{- $logConfigFile := index . "logConfigFile" | default (printf "/etc/%s/logging.conf" $serviceName ) -}}
{{- $tlsSecret := index . "tlsSecret" | default "" -}}
{{- $keystoneUser := index . "keystoneUser" | default $serviceName -}}
{{- $keystoneUserSystem := index . "keystoneUserSystem" | default "admin-system" }}
{{- $openrc := index . "openrc" | default "true" -}}
{{- $secretBin := index . "secretBin" -}}
{{- $backoffLimit := index . "backoffLimit" | default "20" -}}
{{- $activeDeadlineSeconds := index . "activeDeadlineSeconds" -}}
{{- $serviceNamePretty := $serviceName | replace "_" "-" -}}
{{- $boostrapScript := index . "boostrapScript" | default "bootstrap.sh" }}
{{- $boostrapImage := index . "boostrapImage" | default "bootstrap" }}
{{- $osCloudsSecret :=  index . "osCloudsSecret" | default (printf "%s-%s" $serviceName "os-clouds" ) -}}
{{- $caCert :=  index . "caCert" | default "false" -}}

{{- $serviceAccountName := printf "%s-%s" $serviceNamePretty "bootstrap" }}
{{ tuple $envAll "bootstrap" $serviceAccountName | include "helm-toolkit.snippets.kubernetes_pod_rbac_serviceaccount" }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "%s-%s" $serviceNamePretty "bootstrap" | quote }}
spec:
  backoffLimit: {{ $backoffLimit }}
{{- if $activeDeadlineSeconds }}
  activeDeadlineSeconds: {{ $activeDeadlineSeconds }}
{{- end }}
  template:
    metadata:
      labels:
{{ tuple $envAll $serviceName "bootstrap" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 8 }}
      annotations:
{{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" | indent 8 }}
    spec:
      serviceAccountName: {{ $serviceAccountName }}
{{ dict "envAll" $envAll "application" "bootstrap" | include "helm-toolkit.snippets.kubernetes_pod_security_context" | indent 6 }}
      restartPolicy: OnFailure
      nodeSelector:
{{ toYaml $nodeSelector | indent 8 }}
      initContainers:
{{ tuple $envAll "bootstrap" list | include "helm-toolkit.snippets.kubernetes_entrypoint_init_container"  | indent 8 }}
{{- if eq $caCert "true" }}
{{ tuple $envAll $serviceName "bootstrap" | include "helm-toolkit.snippets.kubernetes_cacert_init_container"  | indent 8 }}
{{- end }}
      containers:
        - name: bootstrap
{{ dict "envAll" $envAll "application" "bootstrap" "container" "bootstrap" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 10 }}
          image: {{ index $envAll.Values.images.tags $boostrapImage }}
          imagePullPolicy: {{ $envAll.Values.images.pull_policy }}
{{ tuple $envAll $envAll.Values.pod.resources.jobs.bootstrap | include "helm-toolkit.snippets.kubernetes_resources" | indent 10 }}
          env:
            - name: NODE_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
{{- if eq $caCert "true" }}
            - name: CURL_CA_BUNDLE
              value: /certs/ca-bundle.pem
            - name: REQUESTS_CA_BUNDLE
              value: /certs/ca-bundle.pem
{{- end }}
{{- if eq $openrc "true" }}
{{- include "helm-toolkit.snippets.keystone_os_cloud_vars" ( dict "osCloudName" $keystoneUser "osCloudNameSystem" $keystoneUserSystem ) | indent 12 }}
{{- end }}
{{ dict "envAll" $envAll | include "helm-toolkit.snippets.kubernetes_proxy_env_vars" | indent 12 }}
          command:
            - /bin/bash
            - -c
            - /tmp/{{ $boostrapScript }}
          volumeMounts:
            - name: pod-tmp
              mountPath: /tmp
            - name: {{ $serviceName }}-bin
              mountPath: /tmp/{{ $boostrapScript }}
              subPath: {{ $boostrapScript }}
              readOnly: true
            - name: os-clouds
              mountPath: /etc/openstack/clouds.yaml
              subPath: clouds.yaml
              readOnly: true
            - name: etc-service
              mountPath: {{ dir $configFile | quote }}
            - name: bootstrap-conf
              mountPath: {{ $configFile | quote }}
              subPath: {{ base $configFile | quote }}
              readOnly: true
            - name: bootstrap-conf
              mountPath: {{ $logConfigFile | quote }}
              subPath: {{ base $logConfigFile | quote }}
              readOnly: true
{{- if eq $caCert "true" }}
{{ dict "envAll" $envAll "objectType" "mountpoint" "secretPrefix" $serviceName  | include "helm-toolkit.snippets.kubernetes_ssl_objects" | indent 12 }}
{{- end }}
{{ dict "enabled" (ne $tlsSecret "") "name" $tlsSecret | include "helm-toolkit.snippets.tls_volume_mount" | indent 12 }}
{{- if $podVolMounts }}
{{ $podVolMounts | toYaml | indent 12 }}
{{- end }}
      volumes:
        - name: pod-tmp
          emptyDir: {}
        - name: os-clouds
          secret:
            secretName: {{ $osCloudsSecret | quote }}
            defaultMode: 416
        - name: {{ $serviceName }}-bin
{{- if $secretBin }}
          secret:
            secretName: {{ $secretBin | quote }}
            defaultMode: 416
{{- else }}
          configMap:
            name: {{ $configMapBin | quote }}
            defaultMode: 504
{{- end }}
        - name: etc-service
          emptyDir: {}
        - name: bootstrap-conf
          secret:
            secretName: {{ $configMapEtc | quote }}
            defaultMode: 416
{{- if eq $caCert "true" }}
{{ dict "envAll" $envAll "objectType" "volume" "secretPrefix" $serviceName  | include "helm-toolkit.snippets.kubernetes_ssl_objects" | indent 8 }}
{{- end }}
{{- dict "enabled" (ne $tlsSecret "") "name" $tlsSecret | include "helm-toolkit.snippets.tls_volume" | indent 8 }}
{{- if $podVols }}
{{ $podVols | toYaml | indent 8 }}
{{- end }}
{{- end }}
