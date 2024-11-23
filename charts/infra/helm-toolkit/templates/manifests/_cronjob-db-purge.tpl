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
To enable security context define the following values:
  pod:
    security_context:
      db_purge:
        pod:
          runAsUser: 65534
        container:
          db_purge:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
*/}}

{{- define "helm-toolkit.manifests.cronjob_db_purge" -}}
{{- $envAll := index . "envAll" -}}
{{- $serviceName := index . "serviceName" -}}
{{- $nodeSelector := index . "nodeSelector" | default (dict $envAll.Values.labels.job.node_selector_key $envAll.Values.labels.job.node_selector_value) -}}
{{- $podVolMounts := index . "podVolMounts" | default false -}}
{{- $podVols := index . "podVols" | default false -}}
{{- $scriptName := index . "scriptName" | default "db-purge.sh" -}}
{{- $configMapAuxiliary := index . "configMapAuxiliary" | default (printf "%s-%s" $serviceName "bin-aux") -}}
{{- $secretEtc := index . "secretEtc" | default (printf "%s-%s" $serviceName "etc") -}}
{{- $configFile := index . "configFile" | default (printf "/etc/%s/%s.conf" $serviceName $serviceName) -}}
{{- $logConfigFile := index . "logConfigFile" | default (printf "/etc/%s/logging.conf" $serviceName) -}}
{{- $jobOptions := index . "jobOptions" | default $envAll.Values.jobs.db_purge -}}
{{- $serviceNamePretty := $serviceName | replace "_" "-" -}}

{{- $serviceAccountName := printf "%s-%s" $serviceNamePretty "db-purge" }}
{{ tuple $envAll "db_purge" $serviceAccountName | include "helm-toolkit.snippets.kubernetes_pod_rbac_serviceaccount" }}
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ $serviceAccountName }}
  annotations:
    {{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" }}
spec:
  schedule: {{ $jobOptions.cron | quote }}
  successfulJobsHistoryLimit: {{ $jobOptions.history.success }}
  failedJobsHistoryLimit: {{ $jobOptions.history.failed }}
  concurrencyPolicy: Forbid
  suspend: {{ not $jobOptions.enabled }}
  jobTemplate:
    metadata:
      labels:
{{ tuple $envAll $serviceName "db-purge" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 8 }}
      annotations:
{{ dict "envAll" $envAll "podName" $serviceAccountName "containerNames" (list "init" $serviceAccountName) | include "helm-toolkit.snippets.kubernetes_mandatory_access_control_annotation" | indent 8 }}
    spec:
      template:
        metadata:
          labels:
{{ tuple $envAll $serviceName "db-purge" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 12 }}
          annotations:
{{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" | indent 12 }}
{{ dict "envAll" $envAll "podName" $serviceAccountName "containerNames" (list "init" $serviceAccountName) | include "helm-toolkit.snippets.kubernetes_mandatory_access_control_annotation" | indent 8 }}
        spec:
          serviceAccountName: {{ $serviceAccountName }}
{{ dict "envAll" $envAll "application" "db_purge" | include "helm-toolkit.snippets.kubernetes_pod_security_context" | indent 10 }}
          restartPolicy: OnFailure
          nodeSelector:
{{ toYaml $nodeSelector | indent 12 }}
          initContainers:
{{ tuple $envAll "db-purge" list | include "helm-toolkit.snippets.kubernetes_entrypoint_init_container"  | indent 12 }}
          containers:
            - name: db-purge
{{ dict "envAll" $envAll "application" "db_purge" "container" "db_purge" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 14 }}
{{ tuple $envAll ($serviceAccountName | replace "-" "_") | include "helm-toolkit.snippets.image" | indent 14 }}
{{ tuple $envAll $envAll.Values.pod.resources.jobs.db_purge | include "helm-toolkit.snippets.kubernetes_resources" | indent 14 }}
              command:
                - /tmp/{{ $scriptName }}
              volumeMounts:
                - name: pod-tmp
                  mountPath: /tmp
                - name: db-purge-script
                  mountPath: /tmp/{{ $scriptName }}
                  subPath: {{ $scriptName }}
                  readOnly: true
                - name: etc-service
                  mountPath: {{ dir $configFile | quote }}
                - name: service-conf
                  mountPath: {{ $configFile | quote }}
                  subPath: {{ base $configFile | quote }}
                  readOnly: true
                - name: service-conf
                  mountPath: {{ $logConfigFile | quote }}
                  subPath: {{ base $logConfigFile | quote }}
                  readOnly: true
{{- if $podVolMounts }}
{{ $podVolMounts | toYaml | indent 16 }}
{{- end }}
          volumes:
            - name: pod-tmp
              emptyDir: {}
            - name: db-purge-script
              configMap:
                name: {{ $configMapAuxiliary | quote }}
                defaultMode: 504
            - name: etc-service
              emptyDir: {}
            - name: service-conf
              secret:
                secretName: {{ $secretEtc | quote }}
                defaultMode: 416
{{- if $podVols }}
{{ $podVols | toYaml | indent 12 }}
{{- end }}
{{- end }}
