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
