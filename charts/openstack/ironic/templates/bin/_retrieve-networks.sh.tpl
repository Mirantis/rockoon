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

set -ex

# Mask permissions to files 416 dirs 0750
umask 0027

touch /tmp/pod-shared/networks.conf
{{- if .Values.network.pxe.convert_cleaning_network_name_to_uuid -}}
IRONIC_NEUTRON_CLEANING_NET_ID=$(openstack network show {{ .Values.network.cleaning.name }} -f value -c id)
if [[ -n $IRONIC_NEUTRON_CLEANING_NET_ID ]]; then
  tee /tmp/pod-shared/networks.conf <<EOF
[neutron]
cleaning_network_uuid = ${IRONIC_NEUTRON_CLEANING_NET_ID}
EOF
fi
{{- end -}}
