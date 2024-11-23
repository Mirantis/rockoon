{{/*
Copyright 2019 Mirantis Inc.

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
  This snippet adds kubernetes objects (mount point, volume) and also adds
  code block in pod start script for passing CA certificate inside pods for
  further requests validation against it. For specifying
  the type of object need to pass "script_sh" or "mountpoint" or "volume" value in "objectType" key
examples:
  - values: |
      manifests:
        configmap_ca_bundle: true
    usage_mountpoint: |
      {{ dict "envAll" $envAll "objectType" "mountpoint" "secretPrefix" "horizon" | include "helm-toolkit.snippets.kubernetes_ssl_objects" | indent 12 }}
    return_mountpoint: |
      - name: ca-cert-bundle
        mountPath: /etc/ssl/certs/openstack-ca-bundle.pem
        readOnly: true
        subPath: ca_bundle
      - name: ca-cert
        mountPath: /certs
    usage_volume: |
      {{ dict "envAll" $envAll "objectType" "volume" "secretPrefix" "horizon" | include "helm-toolkit.snippets.kubernetes_ssl_objects" | indent 8 }}
    return_volume: |
      - name: ca-cert-bundle
        secret:
          secretName: horizon-ca-bundle
      - name: ca-cert
        emptyDir: {}
    usage_script_sh: |
      {{ dict "envAll" $envAll "objectType" "script_sh" "secretPrefix" "horizon" | include "helm-toolkit.snippets.kubernetes_ssl_objects" }}
    return_script_sh: |
      CERTIFI_CA_BUNDLE=`python -c "from requests import certs; print(certs.where())" || true`
      OPENSTACK_CA_BUNDLE="/etc/ssl/certs/openstack-ca-bundle.pem"
      if [[ -f "${CERTIFI_CA_BUNDLE}" && -f "${OPENSTACK_CA_BUNDLE}" ]] ; then
          cat ${CERTIFI_CA_BUNDLE} > /certs/ca-bundle.pem
          cat ${OPENSTACK_CA_BUNDLE} >> /certs/ca-bundle.pem
          export REQUESTS_CA_BUNDLE=/certs/ca-bundle.pem
          export CURL_CA_BUNDLE=${REQUESTS_CA_BUNDLE}
      fi
*/}}

{{- define "helm-toolkit.snippets.kubernetes_ssl_objects" -}}
{{- $envAll := index . "envAll" -}}
{{- if $envAll.Values.manifests.secret_ca_bundle }}
{{- $objectType := index . "objectType" -}}
{{- $secretPrefix := index . "secretPrefix" -}}
{{- if eq $objectType "mountpoint" }}
- name: ca-cert-bundle
  mountPath: /etc/ssl/certs/openstack-ca-bundle.pem
  readOnly: true
  subPath: ca_bundle
- name: ca-cert
  mountPath: /certs
{{- end }}
{{- if eq $objectType "volume" }}
- name: ca-cert-bundle
  secret:
    secretName: {{ $secretPrefix }}-ca-bundle
- name: ca-cert
  emptyDir: {}
{{- end }}
{{- if eq $objectType "script_sh" }}
CERTIFI_CA_BUNDLE=`python -c "from requests import certs; print(certs.where())" || true`
OPENSTACK_CA_BUNDLE="/etc/ssl/certs/openstack-ca-bundle.pem"
if [[ -f "${CERTIFI_CA_BUNDLE}" && -f "${OPENSTACK_CA_BUNDLE}" ]] ; then
    cat ${CERTIFI_CA_BUNDLE} > /certs/ca-bundle.pem
    cat ${OPENSTACK_CA_BUNDLE} >> /certs/ca-bundle.pem
    export REQUESTS_CA_BUNDLE=/certs/ca-bundle.pem
    export CURL_CA_BUNDLE=${REQUESTS_CA_BUNDLE}
fi
{{- end }}
{{- end }}
{{- end }}
