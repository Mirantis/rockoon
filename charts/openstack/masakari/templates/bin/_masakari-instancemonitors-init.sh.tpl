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

libvirt_interface="{{- .Values.conf.libvirt.interface -}}"
if [[ -n $libvirt_interface ]]; then
    # determine ip dynamically based on interface provided
    libvirt_address=$(ip a s $libvirt_interface | grep 'inet ' | awk '{print $2}' | awk -F "/" '{print $1}')
fi

qemu_connection_type="qemu+tcp"
listen_tls="{{- .Values.conf.libvirt.tls -}}"
if [[ $listen_tls == "true" ]]; then
    qemu_connection_type="qemu+tls"
fi

touch /etc/masakarimonitors/masakarimonitors.conf.d/masakarimonitors-libvirt.conf
if [[ -n $libvirt_address ]]; then
cat <<EOF>/etc/masakarimonitors/masakarimonitors.conf.d/masakarimonitors-libvirt.conf
[libvirt]
connection_uri = "${qemu_connection_type}://${libvirt_address}/system"
EOF
else
    echo "Libvirt address is not set."
    exit 1
fi
