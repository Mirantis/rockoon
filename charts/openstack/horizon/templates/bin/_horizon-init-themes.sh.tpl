#!/bin/bash

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

{{- $envAll := . }}

set -ex
CACHE_DIRECTORY=/var/lib/horizon/custom_themes/

function download_theme() {
  local theme_name="$1"
  local url="$2"
  local sha256summ="$3"

  local theme_file="${CACHE_DIRECTORY}/${theme_name}/${url##*/}"
  local theme_folder="${CACHE_DIRECTORY}/${theme_name}/${sha256summ}"

  if [[ -d ${theme_folder} && ! -f ${theme_folder}.completed ]]; then
      echo "Download of ${theme_name} was not finished successfully. Redownloading."
      rm -rf ${CACHE_DIRECTORY}/${theme_name}
  fi

  if ! ls ${theme_folder}; then
    mkdir -p ${CACHE_DIRECTORY}/${theme_name}
    curl --connect-timeout 10 --retry 10 --retry-delay 60 -sSL $url -o $theme_file
    if [[ "$(sha256sum $theme_file | awk '{print $1}')" == "${sha256summ}" ]]; then
        mkdir -p ${CACHE_DIRECTORY}/${theme_name}/${sha256summ}
        tar -xf $theme_file -C ${CACHE_DIRECTORY}/${theme_name}/${sha256summ}
        touch ${theme_folder}.completed
    else
      echo "Downloades theme checksumm mismach."
      rm -f $theme_file
      exit 1
    fi
  fi

}

{{- if hasKey .Values.conf.horizon.local_settings "custom_themes" }}
  {{- range $theme_name, $theme := .Values.conf.horizon.local_settings.custom_themes }}
download_theme {{ $theme_name }} {{ $theme.url }} {{ $theme.sha256summ }}
  if [[ ! -e {{ $envAll.Values.conf.software.horizon.dashboard_path }}/custom_themes/{{ $theme_name }} ]]; then
    ln -s /var/lib/horizon/custom_themes/{{ $theme_name }}/{{ $theme.sha256summ }}/ {{ $envAll.Values.conf.software.horizon.dashboard_path }}/custom_themes/{{ $theme_name }}
  fi
  {{- end }}
{{- end }}
