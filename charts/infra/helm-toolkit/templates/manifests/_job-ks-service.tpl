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

# This function creates a manifest for keystone service management.
# It can be used in charts dict created similar to the following:
# {- $ksServiceJob := dict "envAll" . "serviceName" "senlin" "serviceTypes" ( tuple "clustering" ) -}
# { $ksServiceJob | include "helm-toolkit.manifests.job_ks_service" }

{{/*
To enable security context define the following values:
  pod:
    security_context:
      ks_service:
        pod:
          runAsUser: 65534
        container:
          ks_service:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
*/}}

{{- define "helm-toolkit.manifests.job_ks_service" -}}
{{- $envAll := index . "envAll" -}}
{{- $serviceName := index . "serviceName" -}}
{{- $serviceTypes := index . "serviceTypes" -}}
{{- $nodeSelector := index . "nodeSelector" | default ( dict $envAll.Values.labels.job.node_selector_key $envAll.Values.labels.job.node_selector_value ) -}}
{{- $configMapBin := index . "configMapBin" | default (printf "%s-%s" $serviceName "bin" ) -}}
{{- $secretBin := index . "secretBin" -}}
{{- $tlsSecret := index . "tlsSecret" | default "" -}}
{{- $backoffLimit := index . "backoffLimit" | default "20" -}}
{{- $activeDeadlineSeconds := index . "activeDeadlineSeconds" -}}
{{- $serviceNamePretty := $serviceName | replace "_" "-" -}}
{{- $osCloudsSecret :=  index . "osCloudsSecret" | default (printf "%s-%s" $serviceName "os-clouds" ) -}}
{{- $restartPolicy := index . "restartPolicy" | default "OnFailure" -}}
{{- if hasKey $envAll.Values "jobs" -}}
{{- if hasKey $envAll.Values.jobs "ks_service" -}}
{{- $restartPolicy = $envAll.Values.jobs.ks_service.restartPolicy | default "OnFailure" }}
{{- end }}
{{- end }}

{{- $serviceAccountName := printf "%s-%s" $serviceNamePretty "ks-service" }}
{{ tuple $envAll "ks_service" $serviceAccountName | include "helm-toolkit.snippets.kubernetes_pod_rbac_serviceaccount" }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "%s-%s" $serviceNamePretty "ks-service" | quote }}
spec:
  backoffLimit: {{ $backoffLimit }}
{{- if $activeDeadlineSeconds }}
  activeDeadlineSeconds: {{ $activeDeadlineSeconds }}
{{- end }}
  template:
    metadata:
      labels:
{{ tuple $envAll $serviceName "ks-service" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 8 }}
      annotations:
{{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" | indent 8 }}
    spec:
      serviceAccountName: {{ $serviceAccountName }}
{{ dict "envAll" $envAll "application" "ks_service" | include "helm-toolkit.snippets.kubernetes_pod_security_context" | indent 6 }}
      restartPolicy: {{ $restartPolicy }}
      nodeSelector:
{{ toYaml $nodeSelector | indent 8 }}
      initContainers:
{{ tuple $envAll "ks_service" list | include "helm-toolkit.snippets.kubernetes_entrypoint_init_container" | indent 8 }}
      containers:
{{- range $key1, $osServiceType := $serviceTypes }}
{{- $osServiceTypeDict := index $envAll.Values.endpoints ($osServiceType | replace "-" "_") }}
{{- $enabled := true }}
{{- if hasKey $osServiceTypeDict "enabled" }}
{{- $enabled = $osServiceTypeDict.enabled }}
{{- end }}
{{- if $enabled }}
        - name: {{ printf "%s-%s" $osServiceType "ks-service-registration" | quote }}
          image: {{ $envAll.Values.images.tags.ks_service }}
          imagePullPolicy: {{ $envAll.Values.images.pull_policy }}
{{ tuple $envAll $envAll.Values.pod.resources.jobs.ks_service | include "helm-toolkit.snippets.kubernetes_resources" | indent 10 }}
{{ dict "envAll" $envAll "application" "ks_service" "container" "ks_service" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 10 }}
          command:
            - /tmp/ks-service.py
          volumeMounts:
            - name: pod-tmp
              mountPath: /tmp
            - name: ks-service-py
              mountPath: /tmp/ks-service.py
              subPath: ks-service.py
              readOnly: true
            - name: os-clouds
              mountPath: /etc/openstack/clouds.yaml
              subPath: clouds.yaml
              readOnly: true
{{ dict "enabled" true "name" $tlsSecret "ca" true | include "helm-toolkit.snippets.tls_volume_mount" | indent 12 }}
          env:
{{- include "helm-toolkit.snippets.keystone_os_cloud_vars" ( dict "osCloudName" "admin" ) | indent 12 }}
            - name: OS_SERVICE_NAME
              value: {{ tuple $osServiceType $envAll | include "helm-toolkit.endpoints.keystone_endpoint_name_lookup" }}
            - name: OS_SERVICE_TYPE
              value: {{ $osServiceTypeDict.os_service_type | default $osServiceType | quote }}
            - name: STATE
              value: {{ $osServiceTypeDict.state | default "present" | quote }}
{{- end }}
{{- end }}
      volumes:
        - name: pod-tmp
          emptyDir: {}
        - name: os-clouds
          secret:
            secretName: {{ $osCloudsSecret | quote }}
            defaultMode: 416
        - name: ks-service-py
{{- if $secretBin }}
          secret:
            secretName: {{ $secretBin | quote }}
            defaultMode: 416
{{- else }}
          configMap:
            name: {{ $configMapBin | quote }}
            defaultMode: 504
{{- end }}
{{- dict "enabled" true "name" $tlsSecret | include "helm-toolkit.snippets.tls_volume" | indent 8 }}
{{- end }}
