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

# This function creates a manifest for db migration and management.
# It can be used in charts dict created similar to the following:
# {- $dbSyncJob := dict "envAll" . "serviceName" "senlin" -}
# { $dbSyncJob | include "helm-toolkit.manifests.job_db_sync" }
{{/*
To enable security context define the following values:
  pod:
    security_context:
      db_sync:
        pod:
          runAsUser: 65534
        container:
          db_sync:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
*/}}

{{- define "helm-toolkit.manifests.job_db_sync" -}}
{{- $envAll := index . "envAll" -}}
{{- $serviceName := index . "serviceName" -}}
{{- $nodeSelector := index . "nodeSelector" | default ( dict $envAll.Values.labels.job.node_selector_key $envAll.Values.labels.job.node_selector_value ) -}}
{{- $configMapBin := index . "configMapBin" | default (printf "%s-%s" $serviceName "bin" ) -}}
{{- $configMapEtc := index . "configMapEtc" | default (printf "%s-%s" $serviceName "etc" ) -}}
{{- $podVolMounts := index . "podVolMounts" | default false -}}
{{- $podVols := index . "podVols" | default false -}}
{{- $podEnvVars := index . "podEnvVars" | default false -}}
{{- $dbToSync := index . "dbToSync" | default ( dict "configFile" (printf "/etc/%s/%s.conf" $serviceName $serviceName ) "logConfigFile" (printf "/etc/%s/logging.conf" $serviceName ) "image" ( index $envAll.Values.images.tags ( printf "%s_db_sync" $serviceName )) ) -}}
{{- $secretBin := index . "secretBin" -}}
{{- $backoffLimit := index . "backoffLimit" | default "20" -}}
{{- $activeDeadlineSeconds := index . "activeDeadlineSeconds" -}}
{{- $serviceNamePretty := $serviceName | replace "_" "-" -}}
{{- $extraHashes := index . "extraHashes" | default dict -}}

{{- $serviceAccountName := printf "%s-%s" $serviceNamePretty "db-sync" }}
{{ tuple $envAll "db_sync" $serviceAccountName | include "helm-toolkit.snippets.kubernetes_pod_rbac_serviceaccount" }}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ printf "%s-%s" $serviceNamePretty "db-sync" | quote }}
spec:
  backoffLimit: {{ $backoffLimit }}
{{- if $activeDeadlineSeconds }}
  activeDeadlineSeconds: {{ $activeDeadlineSeconds }}
{{- end }}
  template:
    metadata:
      labels:
{{ tuple $envAll $serviceName "db-sync" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 8 }}
      annotations:
{{ tuple $envAll | include "helm-toolkit.snippets.release_uuid" | indent 8 }}
        endpoints-oslo-db-hash: {{ $envAll.Values.endpoints.oslo_db | include "helm-toolkit.utils.get_hash" }}
{{- range $key,$val := $extraHashes }}
        {{ $key }}: {{ $val }}
{{- end }}
    spec:
      serviceAccountName: {{ $serviceAccountName }}
{{ dict "envAll" $envAll "application" "db_sync" | include "helm-toolkit.snippets.kubernetes_pod_security_context" | indent 6 }}
      restartPolicy: OnFailure
      nodeSelector:
{{ toYaml $nodeSelector | indent 8 }}
      initContainers:
{{ tuple $envAll "db_sync" list | include "helm-toolkit.snippets.kubernetes_entrypoint_init_container" | indent 8 }}
      containers:
        - name: {{ printf "%s-%s" $serviceNamePretty "db-sync" | quote }}
          image: {{ $dbToSync.image | quote }}
          imagePullPolicy: {{ $envAll.Values.images.pull_policy | quote }}
{{ dict "envAll" $envAll "application" "db_sync" "container" "db_sync" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 10 }}
{{ tuple $envAll $envAll.Values.pod.resources.jobs.db_sync | include "helm-toolkit.snippets.kubernetes_resources" | indent 10 }}
{{- if $podEnvVars }}
          env:
{{ $podEnvVars | toYaml | indent 12 }}
{{- end }}
          command:
            - /bin/bash
            - -c
            - /tmp/db-sync.sh
          volumeMounts:
            - name: pod-tmp
              mountPath: /tmp
            - name: db-sync-sh
              mountPath: /tmp/db-sync.sh
              subPath: db-sync.sh
              readOnly: true
            - name: etc-service
              mountPath: {{ dir $dbToSync.configFile | quote }}
            - name: db-sync-conf
              mountPath: {{ $dbToSync.configFile | quote }}
              subPath: {{ base $dbToSync.configFile | quote }}
              readOnly: true
            - name: db-sync-conf
              mountPath: {{ $dbToSync.logConfigFile | quote }}
              subPath: {{ base $dbToSync.logConfigFile | quote }}
              readOnly: true
{{- if $podVolMounts }}
{{ $podVolMounts | toYaml | indent 12 }}
{{- end }}
      volumes:
        - name: pod-tmp
          emptyDir: {}
        - name: db-sync-sh
{{- if $secretBin }}
          secret:
            secretName: {{ $secretBin | quote }}
            defaultMode: 416
{{- else }}
          configMap:
            name: {{ $configMapBin | quote }}
            defaultMode: 360
{{- end }}
        - name: etc-service
          emptyDir: {}
        - name: db-sync-conf
          secret:
            secretName: {{ $configMapEtc | quote }}
            defaultMode: 416
{{- if $podVols }}
{{ $podVols | toYaml | indent 8 }}
{{- end }}
{{- end }}
