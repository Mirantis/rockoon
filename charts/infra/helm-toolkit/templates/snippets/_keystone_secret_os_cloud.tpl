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

{{- define "helm-toolkit.snippets.keystone_secret_os_cloud" }}
{{- $identityEndpoints := index . 0 -}}
{{- $context := index . 1 -}}
{{- $authContext := index $context.Values.endpoints.identity.auth }}
clouds:
{{- if kindIs "slice" $identityEndpoints }}
{{- range $identityEndpoint := $identityEndpoints }}
  {{- range $contextName, $userContext := $authContext }}
    {{ $contextName }}-{{ $identityEndpoint }}:
      auth:
        auth_url: {{ tuple "identity" $identityEndpoint "api" $context | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" }}
        username: {{ $userContext.username }}
        password: {{ $userContext.password }}
        project_name: {{ $userContext.project_name }}
        project_domain_name: {{ $userContext.project_domain_name }}
        user_domain_name: {{ $userContext.user_domain_name }}
      region_name: {{ $userContext.region_name }}
      identity_api_version: 3
      interface: {{ $identityEndpoint }}
      # Unless PRODX-23446 is fixed
      endpoint_type: {{ $identityEndpoint }}
    {{ $contextName }}-system-{{ $identityEndpoint }}:
      auth:
        auth_url: {{ tuple "identity" $identityEndpoint "api" $context | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" }}
        username: {{ $userContext.username }}
        password: {{ $userContext.password }}
        user_domain_name: {{ $userContext.user_domain_name }}
        system_scope: all
      region_name: {{ $userContext.region_name }}
      identity_api_version: 3
      interface: {{ $identityEndpoint }}
      # Unless PRODX-23446 is fixed
      endpoint_type: {{ $identityEndpoint }}
  {{- end }}
{{- end }}
{{- else if kindIs "string" $identityEndpoints }}
{{- $identityEndpoint := $identityEndpoints -}}
{{- range $contextName, $userContext := $authContext }}
  {{ $contextName }}:
    auth:
      auth_url: {{ tuple "identity" $identityEndpoint "api" $context | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" }}
      username: {{ $userContext.username }}
      password: {{ $userContext.password }}
      project_name: {{ $userContext.project_name }}
      project_domain_name: {{ $userContext.project_domain_name }}
      user_domain_name: {{ $userContext.user_domain_name }}
    region_name: {{ $userContext.region_name }}
    identity_api_version: 3
    interface: {{ $identityEndpoint }}
    # Unless PRODX-23446 is fixed
    endpoint_type: {{ $identityEndpoint }}
  {{ $contextName }}-system:
    auth:
      auth_url: {{ tuple "identity" $identityEndpoint "api" $context | include "helm-toolkit.endpoints.keystone_endpoint_uri_lookup" }}
      username: {{ $userContext.username }}
      password: {{ $userContext.password }}
      user_domain_name: {{ $userContext.user_domain_name }}
      system_scope: all
    region_name: {{ $userContext.region_name }}
    identity_api_version: 3
    interface: {{ $identityEndpoint }}
    # Unless PRODX-23446 is fixed
    endpoint_type: {{ $identityEndpoint }}
{{- end }}
{{- end }}
{{- end }}
