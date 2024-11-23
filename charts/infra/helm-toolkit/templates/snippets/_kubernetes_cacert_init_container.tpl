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
  Returns a container definition for use with the script for initiating
  ca certs from helm-toolkit.snippets.kubernetes_ssl_objects.
values: |
  # if the stanza, or a portion of it, under `pod` is not
  # specififed then the following will be used as defaults:
  #  pod:
  #    security_context:
  #      cacert_init:
  #        container:
  #          cacert_init:
  #            readOnlyRootFilesystem: true
  #            allowPrivilegeEscalation: false
  #            capabilities:
  #              drop:
  #              - ALL
  pod:
    security_context:
      cacert_init:
        container:
          cacert_init:
            runAsUser: 0
            readOnlyRootFilesystem: false
usage: |
  {{ tuple . "aodh" "bootstrap" | include "helm-toolkit.snippets.kubernetes_cacert_init_container" }}
return: |
  - name: cacert-init
    command:
      - /tmp/cacert-init.sh
    image: docker-dev-kaas-virtual.docker.mirantis.net/openstack/heat:antelope-jammy-20231013164438
    imagePullPolicy: IfNotPresent
    name: cacert-init
    volumeMounts:
    - mountPath: /etc/ssl/certs/openstack-ca-bundle.pem
      name: ca-cert-bundle
      readOnly: true
      subPath: ca_bundle
    - mountPath: /certs
      name: ca-cert
    - mountPath: /tmp/cacert-init.sh
      name: aodh-bin
      readOnly: true
      subPath: cacert-init.sh
*/}}

{{- define "helm-toolkit.snippets.kubernetes_cacert_init_container._default_security_context" -}}
Values:
  pod:
    security_context:
      cacert_init:
        container:
          cacert_init:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
{{- end -}}

{{- define "helm-toolkit.snippets.kubernetes_cacert_init_container" -}}
{{- $envAll := index . 0 -}}
{{- $serviceName := index . 1 -}}
{{- $imageTag := index . 2 -}}

{{- $default_security_context := include "helm-toolkit.snippets.kubernetes_cacert_init_container._default_security_context" . | fromYaml }}
{{- $patchedEnvAll := mergeOverwrite $default_security_context $envAll }}
- name: cacert-init
{{- dict "envAll" $patchedEnvAll "application" "cacert_init" "container" "cacert_init" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 2 }}
{{ tuple $envAll $imageTag | include "helm-toolkit.snippets.image" | indent 2 }}
  command:
    - /tmp/cacert-init.sh
  volumeMounts:
{{ dict "envAll" $envAll "objectType" "mountpoint" "secretPrefix" $serviceName | include "helm-toolkit.snippets.kubernetes_ssl_objects" | indent 4 }}
    - name: {{ $serviceName }}-bin
      mountPath: /tmp/cacert-init.sh
      subPath: cacert-init.sh
      readOnly: true
{{- end -}}