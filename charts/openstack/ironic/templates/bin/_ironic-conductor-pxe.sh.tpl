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
FILE_TO_CHECK=is_alive.txt

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

echo "Ok" > /var/lib/openstack-helm/tftpboot/${FILE_TO_CHECK}

cat <<EOF >/tmp/pxe-health-probe.sh
#!/bin/bash
curl --fail tftp://${PXE_IP}/${FILE_TO_CHECK}
EOF

chmod +x /tmp/pxe-health-probe.sh

ln -s /var/lib/openstack-helm/tftpboot /tftpboot
exec /usr/sbin/in.tftpd \
  --verbose \
  --foreground \
  --user root \
  --address ${PXE_IP}:69 \
  --map-file /tftp-map-file /tftpboot
