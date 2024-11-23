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
{{- $security_driver := index .Values.conf.qemu "security_driver" | default "" }}

set -ex
export HOME=/tmp
KVM_QEMU_CONF_HOST="/etc/modprobe.d_host/qemu-system-x86.conf"

if [[ ! -f "${KVM_QEMU_CONF_HOST}" ]]; then

  if grep vmx /proc/cpuinfo; then
    cat << EOF > ${KVM_QEMU_CONF_HOST}
options kvm_intel nested=1
options kvm_intel enable_apicv=1
options kvm_intel ept=1
EOF

    modprobe -r kvm_intel || true
    modprobe kvm_intel nested=1
  elif grep svm /proc/cpuinfo; then
    cat << EOF > ${KVM_QEMU_CONF_HOST}
options kvm_amd nested=1
EOF
    modprobe -r kvm_amd || true
    modprobe kvm_amd nested=1
  else
    echo "Nested virtualization is not supported"
  fi

fi

{{ if eq $security_driver "apparmor" }}
cp -r /etc/apparmor.d/libvirt /mnt/host-rootfs/etc/apparmor.d/
profiles_dir="/etc/apparmor.d"
profiles_bak_dir="/var/lib/libvirt/apparmor.bak"
mkdir -p "${profiles_bak_dir}"
for prof in usr.sbin.libvirtd usr.lib.libvirt.virt-aa-helper; do
    [[ -f ${profiles_dir}/${prof} ]] || (echo "Apparmor profile ${prof} does not exist" && exit 1)
    # unload profile for case when profile definition was changed, to avoid issues related to
    # profile name change.
    if ! cmp -s "${profiles_dir}/${prof}" "${profiles_bak_dir}/${prof}"; then
        apparmor_parser -R "${profiles_bak_dir}/${prof}" || true
    fi
    # reload profile anyway, as files can be the same but profile can be not loaded in kernel yet
    apparmor_parser -r "${profiles_dir}/${prof}"
    cp "${profiles_dir}/${prof}" "${profiles_bak_dir}/${prof}"
done
{{ end }}

exit 0
