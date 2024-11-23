{{/*
Copyright 2022 Mirantis Inc.

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
usage: |
  conf:
    apache_wsgi_api:
      config:
        keepalive_timeout: 75  # This is optional parameter
        user_ident: barbican
        script_name: barbican-wsgi-api
        processes: 8
        service_name: key_manager
        endpoint:
          type: key_manager
          endpoint: internal
          port: api
      template: |
        {{ include "helm-toolkit.snippets.apache_wsgi_config" ( tuple $ .Values.conf.apache_wsgi_api ) }}

*/}}
{{- define "helm-toolkit.snippets.apache_wsgi_config" }}
{{- $context := index . 0 -}}
{{- $wsgi_config := index . 1 -}}
{{- $scriptName := index $wsgi_config.config "script_name" -}}
{{- $userIdent := index $wsgi_config.config "user_ident" -}}

{{- $endpoint_type := index $wsgi_config.config.endpoint "type" -}}
{{- $endpoint_endpoint := index $wsgi_config.config.endpoint "endpoint" -}}
{{- $endpoint_port := index $wsgi_config.config.endpoint "port" -}}

{{- $portInt := tuple $endpoint_type $endpoint_endpoint $endpoint_port $context | include "helm-toolkit.endpoints.endpoint_port_lookup" }}
{{- $processes := index $wsgi_config.config "processes" -}}
{{- $keepalive_timeout := index $wsgi_config.config "keepalive_timeout" -}}

Listen 0.0.0.0:{{ $portInt }}

LogFormat "%h %l %u %t \"%r\" %>s %b %D \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%{X-Forwarded-For}i %l %u %t \"%r\" %>s %b %D \"%{Referer}i\" \"%{User-Agent}i\"" proxy

SetEnvIf X-Forwarded-For "^.*\..*\..*\..*" forwarded
CustomLog /dev/stdout combined env=!forwarded
CustomLog /dev/stdout proxy env=forwarded

<VirtualHost *:{{ $portInt }}>
    {{ if $keepalive_timeout -}} KeepAliveTimeout {{ $keepalive_timeout }} {{- end }}
    WSGIDaemonProcess {{ $scriptName }} processes={{ $processes }} threads=1 user={{ $userIdent }} group={{ $userIdent }} display-name=%{GROUP}
    WSGIProcessGroup {{ $scriptName }}
    WSGIScriptAlias / /var/www/cgi-bin/{{ $userIdent }}/{{ $scriptName }}
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On
    <IfVersion >= 2.4>
      ErrorLogFormat "%{cu}t %M"
    </IfVersion>
    ErrorLog /dev/stdout

    SetEnvIf X-Forwarded-For "^.*\..*\..*\..*" forwarded
    CustomLog /dev/stdout combined env=!forwarded
    CustomLog /dev/stdout proxy env=forwarded
</VirtualHost>
{{- end }}
