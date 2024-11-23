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
  Creates a manifest for a services public tls secret
values: |
  endpoints:
    identity:
      name: keystone
      auth:
        admin:
          region_name: RegionOne
          username: admin
          password: password
          project_name: admin
          user_domain_name: default
          project_domain_name: default
        glance:
          role: admin
          region_name: RegionOne
          username: glance
          password: password
          project_name: service
          user_domain_name: service
          project_domain_name: service
usage: |
  {{- include "helm-toolkit.manifests.secret_os_clouds" ( dict "envAll" . "serviceName" "glance" ) -}}
return: |
  ---
  apiVersion: v1
  kind: Secret
  metadata:
    name: glance-os-clouds
  type: Opaque
  data:
    clouds.yaml: Y2xvdWRzOgogIGFkbWluOgogICAgYXV0aDoKICAgICAgYXV0aF91cmw6IGh0dHA6Ly9rZXlzdG9uZS1hcGkub3BlbnN0YWNrLnN2Yy5jbHVzdGVyLmxvY2FsOjUwMDAvdjMKICAgICAgdXNlcm5hbWU6IGFkbWluCiAgICAgIHByb2plY3RfbmFtZTogYWRtaW4KICAgICAgcHJvamVjdF9kb21haW5fbmFtZTogZGVmYXVsdAogICAgICB1c2VyX2RvbWFpbl9uYW1lOiBkZWZhdWx0CiAgICByZWdpb25fbmFtZTogUmVnaW9uT25lCiAgICBpZGVudGl0eV9hcGlfdmVyc2lvbjogMwogIGFkbWluLXN5c3RlbToKICAgIGF1dGg6CiAgICAgIGF1dGhfdXJsOiBodHRwOi8va2V5c3RvbmUtYXBpLm9wZW5zdGFjay5zdmMuY2x1c3Rlci5sb2NhbDo1MDAwL3YzCiAgICAgIHVzZXJuYW1lOiBhZG1pbgogICAgICB1c2VyX2RvbWFpbl9uYW1lOiBkZWZhdWx0CiAgICAgIHN5c3RlbV9zY29wZTogYWxsCiAgICByZWdpb25fbmFtZTogUmVnaW9uT25lCiAgICBpZGVudGl0eV9hcGlfdmVyc2lvbjogMwogIGdsYW5jZToKICAgIGF1dGg6CiAgICAgIGF1dGhfdXJsOiBodHRwOi8va2V5c3RvbmUtYXBpLm9wZW5zdGFjay5zdmMuY2x1c3Rlci5sb2NhbDo1MDAwL3YzCiAgICAgIHVzZXJuYW1lOiBnbGFuY2UKICAgICAgcHJvamVjdF9uYW1lOiBzZXJ2aWNlCiAgICAgIHByb2plY3RfZG9tYWluX25hbWU6IHNlcnZpY2UKICAgICAgdXNlcl9kb21haW5fbmFtZTogc2VydmljZQogICAgcmVnaW9uX25hbWU6IFJlZ2lvbk9uZQogICAgaWRlbnRpdHlfYXBpX3ZlcnNpb246IDMKICBnbGFuY2Utc3lzdGVtOgogICAgYXV0aDoKICAgICAgYXV0aF91cmw6IGh0dHA6Ly9rZXlzdG9uZS1hcGkub3BlbnN0YWNrLnN2Yy5jbHVzdGVyLmxvY2FsOjUwMDAvdjMKICAgICAgdXNlcm5hbWU6IGdsYW5jZQogICAgICB1c2VyX2RvbWFpbl9uYW1lOiBzZXJ2aWNlCiAgICAgIHN5c3RlbV9zY29wZTogYWxsCiAgICByZWdpb25fbmFtZTogUmVnaW9uT25lCiAgICBpZGVudGl0eV9hcGlfdmVyc2lvbjogMw==
*/}}

{{- define "helm-toolkit.manifests.secret_os_clouds" }}
{{- $envAll := index . "envAll" }}
{{- $serviceName := index . "serviceName" }}
{{- $endpoint := index . "endpoint" | default "internal" }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{ $serviceName }}-os-clouds
  labels:
{{ tuple $envAll $serviceName "os-clouds" | include "helm-toolkit.snippets.kubernetes_metadata_labels" | indent 4 }}
type: Opaque
data:
  clouds.yaml: {{ tuple $endpoint $envAll | include "helm-toolkit.snippets.keystone_secret_os_cloud" | b64enc }}
{{- end }}
