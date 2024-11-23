{{/*
Copyright 2019 The Openstack-Helm Authors.

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
  {{ include "helm-toolkit.snippets.apache_wsgi" ( tuple "neutron-api" "neutron" 9696 4 ) }}
*/}}
{{- define "helm-toolkit.snippets.apache_wsgi" }}
{{- $scriptName := index . 0 -}}
{{- $userIdent := index . 1 -}}
{{- $portInt := index . 2 -}}
{{- $processes := index . 3 -}}
Listen 0.0.0.0:{{ $portInt }}

LogFormat "%h %l %u %t \"%r\" %>s %b %D \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%{X-Forwarded-For}i %l %u %t \"%r\" %>s %b %D \"%{Referer}i\" \"%{User-Agent}i\"" proxy

SetEnvIf X-Forwarded-For "^.*\..*\..*\..*" forwarded
CustomLog /dev/stdout combined env=!forwarded
CustomLog /dev/stdout proxy env=forwarded

<VirtualHost *:{{ $portInt }}>
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
