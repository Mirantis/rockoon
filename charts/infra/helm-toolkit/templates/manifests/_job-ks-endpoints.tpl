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
# {- $ksEndpointJob := dict "envAll" . "serviceName" "senlin" "serviceTypes" ( tuple "clustering" ) -}
# { $ksEndpointJob | include "helm-toolkit.manifests.job_ks_endpoints" }

{{/*
To enable security context define the following values:
  pod:
    security_context:
      ks_endpoints:
        pod:
          runAsUser: 65534
        container:
          ks_endpoints:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
*/}}

{{- define "helm-toolkit.manifests.job_ks_endpoints" -}}
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
{{- $restartPolicy := index . "restartPolicy" | default "OnFailure" -}}
{{- $osCloudsSecret :=  index . "osCloudsSecret" | default (printf "%s-%s" $serviceName "os-clouds" ) -}}
{{- if hasKey $envAll.Values "jobs" -}}
{{- if hasKey $envAll.Values.jobs "ks_endpoints" -}}
{{- $restartPolicy = $envAll.Values.jobs.ks_endpoints.restartPolicy | default "OnFailure" }}
{{- end }}
{{- end }}

{{- $serviceAccountName := printf "%s-%s" $serviceNamePretty "ks-endpoints" }}
{{ tuple $envAll "ks_endpoints" $serviceAccountName | include "helm-toolkit.snippets.kubernetes_pod_rbac_serviceaccount" }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "%s-%s" $serviceNamePretty "ks-endpoints" | quote }}
spec:
  backoffLimit: {{ $backoffLimit }}
{{- if $activeDeadlineSeconds }}
  activeDeadlineSeconds: {{ $activeDeadlineSeconds }}
{{- end }}
  template:
    metadata:
      labels:
{{ tuple $envAll $serviceName "ks-endpoints" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 8 }}
      annotations:
{{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" | indent 8 }}
    spec:
      serviceAccountName: {{ $serviceAccountName }}
{{ dict "envAll" $envAll "application" "ks_endpoints" | include "helm-toolkit.snippets.kubernetes_pod_security_context" | indent 6 }}
      restartPolicy: {{ $restartPolicy }}
      nodeSelector:
{{ toYaml $nodeSelector | indent 8 }}
      initContainers:
{{ tuple $envAll "ks_endpoints" list | include "helm-toolkit.snippets.kubernetes_entrypoint_init_container" | indent 8 }}
      containers:
{{- range $key1, $osServiceType := $serviceTypes }}
{{- $osServiceTypeDict := index $envAll.Values.endpoints ($osServiceType | replace "-" "_") }}
{{- $enabled := true }}
{{- if hasKey $osServiceTypeDict "enabled" }}
{{- $enabled = $osServiceTypeDict.enabled }}
{{- end }}
{{- if $enabled }}
{{- range $key2, $osServiceEndPoint := tuple "admin" "internal" "public" }}
        - name: {{ printf "%s-%s-%s" $osServiceType "ks-endpoints" $osServiceEndPoint | quote }}
          image: {{ $envAll.Values.images.tags.ks_endpoints }}
          imagePullPolicy: {{ $envAll.Values.images.pull_policy }}
{{ tuple $envAll $envAll.Values.pod.resources.jobs.ks_endpoints | include "helm-toolkit.snippets.kubernetes_resources" | indent 10 }}
{{ dict "envAll" $envAll "application" "ks_endpoints" "container" "ks_endpoints" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 10 }}
          command:
            - /tmp/ks-endpoints.py
          volumeMounts:
            - name: pod-tmp
              mountPath: /tmp
            - name: ks-endpoints-py
              mountPath: /tmp/ks-endpoints.py
              subPath: ks-endpoints.py
              readOnly: true
            - name: os-clouds
              mountPath: /etc/openstack/clouds.yaml
              subPath: clouds.yaml
              readOnly: true
{{ dict "enabled" true "name" $tlsSecret "ca" true | include "helm-toolkit.snippets.tls_volume_mount" | indent 12 }}
          env:
{{- include "helm-toolkit.snippets.keystone_os_cloud_vars" ( dict "osCloudName" "admin" ) | indent 12 }}
            - name: OS_SVC_ENDPOINT
              value: {{ $osServiceEndPoint | quote }}
            - name: OS_SERVICE_NAME
              value: {{ tuple $osServiceType $envAll | include "helm-toolkit.endpoints.keystone_endpoint_name_lookup" }}
            - name: OS_SERVICE_TYPE
              value: {{ $osServiceTypeDict.os_service_type | default $osServiceType | quote }}
            - name: OS_SERVICE_ENDPOINT
              value: {{ tuple $osServiceType $osServiceEndPoint "api" $envAll | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" | quote }}
            - name: STATE
              value: {{ $osServiceTypeDict.state | default "present" | quote }}
{{- end }}
{{- end }}
{{- end }}
      volumes:
        - name: pod-tmp
          emptyDir: {}
        - name: os-clouds
          secret:
            secretName: {{ $osCloudsSecret | quote }}
            defaultMode: 416
        - name: ks-endpoints-py
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
