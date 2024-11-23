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
  Povides ceph keyring management for a Kubernetes container.
examples:
  - values: |
      conf:
        ceph:
          keyrings:
            admin:
              key: AQA8VThkABvsBBAAVd3MeDj6yS6kbiriqtUkIg==
            cinder:
              key: AQA8VThkABvsBBAAVd3MeDj6yS6kbiriqtUkIg==
            nova:
              key: AQA+VThkFpMeJBAAwZr1oBPeNf+W5DxHeZx04Q==


    usage: |
      {{ dict "envAll" . "objectType" "mountpoint" "application" "myApp" | include "helm-toolkit.snippets.kubernetes_ceph_keyring_objects" }}

    return: |
      - name: myApp-etc
        mountPath: /etc/ceph/ceph.client.admin.keyring
        subPath: ceph.client.admin.keyring
        readOnly: true
      - name: myApp-etc
        mountPath: /etc/ceph/ceph.client.cinder.keyring
        subPath: ceph.client.cinder.keyring
        readOnly: true
      - name: myApp-etc
        mountPath: /etc/ceph/ceph.client.nova.keyring
        subPath: ceph.client.nova.keyring
        readOnly: true
========================================================
    usage: |
      {{ dict "envAll" . "objectType" "secret_entry" | include "helm-toolkit.snippets.kubernetes_ceph_keyring_objects" }}

    return: |
      ceph.client.admin.keyring: W2NsaWVudC5hZG1pbl0KICBrZXkgPSBBUUE4VlRoa0FCdnNCQkFBVmQzTWVEajZ5UzZrYmlyaXF0VWtJZz0=
      ceph.client.cinder.keyring: W2NsaWVudC5jaW5kZXJdCiAga2V5ID0gQVFBOFZUaGtBQnZzQkJBQVZkM01lRGo2eVM2a2JpcmlxdFVrSWc9PQ==
      ceph.client.nova.keyring: W2NsaWVudC5ub3ZhXQogIGtleSA9IEFRQStWVGhrRnBNZUpCQUF3WnIxb0JQZU5mK1c1RHhIZVp4MDRRPT0=
*/}}

{{- define "helm-toolkit.snippets.kubernetes_ceph_keyring_objects._compose_entry" -}}
{{- $user := index . 0 -}}
{{- $values := index . 1 -}}
[client.{{ $user }}]
  key = {{ $values.key }}
{{ end -}}

{{- define "helm-toolkit.snippets.kubernetes_ceph_keyring_objects" -}}
{{- $envAll := index . "envAll" -}}
{{- $objectType := index . "objectType" -}}
{{- $application := index . "application" -}}
  {{- if eq $objectType "mountpoint" -}}
    {{- range $user, $_ := $envAll.Values.conf.ceph.keyrings }}
- name: {{ $application }}-etc
  mountPath: /etc/ceph/ceph.client.{{ $user }}.keyring
  subPath: ceph.client.{{ $user }}.keyring
  readOnly: true
    {{- end }}
  {{- end -}}
  {{- if eq $objectType "secret_entry" -}}
    {{- range $user, $values := $envAll.Values.conf.ceph.keyrings }}
ceph.client.{{ $user }}.keyring: {{ tuple $user $values | include "helm-toolkit.snippets.kubernetes_ceph_keyring_objects._compose_entry" | b64enc }}
    {{- end -}}
  {{- end -}}
{{- end -}}
