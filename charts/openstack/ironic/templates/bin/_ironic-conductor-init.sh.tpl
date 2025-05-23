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

mkdir -p /var/lib/openstack-helm/tftpboot
mkdir -p /var/lib/openstack-helm/tftpboot/master_images

for FILE in undionly.kpxe ipxe.efi pxelinux.0; do
  if [ -f /usr/lib/ipxe/$FILE ]; then
    cp -v /usr/lib/ipxe/$FILE /var/lib/openstack-helm/tftpboot
  fi
done

# Mask permissions to files 416 dirs 0750
umask 0027

mkdir -p /var/lib/openstack-helm/httpboot

if [ "x" == "x${PROVISIONER_INTERFACE}" ]; then
  echo "Provisioner interface is not set"
  exit 1
fi

function net_pxe_addr {
 ip addr | awk "/inet / && /${PROVISIONER_INTERFACE}/{print \$2; exit }"
}
function net_pxe_ip {
 echo $(net_pxe_addr) | awk -F '/' '{ print $1; exit }'
}
PXE_IP=$(net_pxe_ip)

if [ "x" == "x${PXE_IP}" ]; then
  echo "Could not find IP for pxe to bind to"
  exit 1
fi

sed "s|OSH_PXE_IP|${PXE_IP}|g" /etc/nginx/nginx.conf > /tmp/pod-shared/nginx.conf

tee /tmp/pod-shared/conductor-local-ip.conf << EOF
[DEFAULT]

# IP address of this host. If unset, will determine the IP
# programmatically. If unable to do so, will use "127.0.0.1".
# (string value)
my_ip = ${PXE_IP}

[pxe]
# IP address of ironic-conductor node's TFTP server. (string
# value)
tftp_server = ${PXE_IP}

[deploy]
# ironic-conductor node's HTTP server URL. Example:
# http://192.1.2.3:8080 (string value)
# from .deploy.ironic.http_url
http_url = http://${PXE_IP}:{{ tuple "baremetal" "internal" "pxe_http" . | include "helm-toolkit.endpoints.endpoint_port_lookup" }}
{{- if .Values.network.api.node_port.enabled }}

[service_catalog]
endpoint_override = http://${PXE_IP}:{{ .Values.network.api.node_port.port }}

{{- end }}
EOF
