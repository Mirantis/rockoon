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

# Make the Nova Instances Dir as this is not autocreated.
mkdir -p /var/lib/nova/instances

# copy private key for cold migrations
install -Dm 400 -o ${NOVA_USER_UID} -t /var/lib/nova/.ssh /root/.ssh/id_rsa
install -Dm 440 -o ${NOVA_USER_UID} -t /var/lib/nova/.ssh /root/.ssh/authorized_keys
install -Dm 444 -t /var/lib/nova/.ssh /root/.ssh/config

# Set Ownership of nova dirs to the nova user
chown ${NOVA_USER_UID} /var/lib/nova /var/lib/nova/instances

migration_interface="{{- .Values.conf.libvirt.live_migration_interface -}}"
if [[ -n $migration_interface ]]; then
    # determine ip dynamically based on interface provided
    migration_address=$(ip a s $migration_interface | grep 'inet ' | awk '{print $2}' | awk -F "/" '{print $1}')
fi

qemu_connection_type="qemu+tcp"
listen_tls="{{- .Values.conf.nova.libvirt.live_migration_with_native_tls -}}"
if [[ $listen_tls == "true" ]]; then
    qemu_connection_type="qemu+tls"
fi

touch /etc/nova/nova.conf.d/nova-libvirt.conf
if [[ -n $migration_address ]]; then
cat <<EOF>/etc/nova/nova.conf.d/nova-libvirt.conf
[libvirt]
live_migration_inbound_addr = $migration_address
connection_uri = "${qemu_connection_type}://${migration_address}/system"
EOF
else
    echo "Migration address is not set."
    exit 1
fi
chgrp ${NOVA_USER_UID} /etc/nova/nova.conf.d/nova-libvirt.conf

hypervisor_interface="{{- .Values.conf.hypervisor.host_interface -}}"
if [[ -z $hypervisor_interface ]]; then
    # search for interface with default routing
    # If there is not default gateway, exit
    hypervisor_interface=$(ip -4 route list 0/0 | awk -F 'dev' '{ print $2; exit }' | awk '{ print $1 }') || exit 1
fi

hypervisor_address=$(ip a s $hypervisor_interface | grep 'inet ' | awk '{print $2}' | awk -F "/" '{print $1}')

if [ -z "${hypervisor_address}" ] ; then
  echo "Var my_ip is empty"
  exit 1
fi

tee > /etc/nova/nova.conf.d/nova-hypervisor.conf << EOF
[DEFAULT]
my_ip  = $hypervisor_address
EOF
chgrp ${NOVA_USER_UID} /etc/nova/nova.conf.d/nova-hypervisor.conf

{{- if and ( empty .Values.conf.nova.DEFAULT.host ) ( .Values.pod.use_fqdn.compute ) }}
tee > /etc/nova/nova.conf.d/nova-compute-fqdn.conf << EOF
[DEFAULT]
host = $(hostname --fqdn)
EOF
chgrp ${NOVA_USER_UID} /etc/nova/nova.conf.d/nova-compute-fqdn.conf
{{- end }}
