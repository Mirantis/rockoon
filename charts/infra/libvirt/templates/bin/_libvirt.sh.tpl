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

function ensure_ceph_secret {
  local secret_name=$1
  local secret_uuid=$2
  local keyring_data=$3

  tmpsecret=$(mktemp --suffix ${secret_name}.xml)
  CLEANUP_FILES="$CLEANUP_FILES ${tmpsecret}"

  cat > ${tmpsecret} <<EOF
<secret ephemeral='no' private='no'>
  <uuid>${secret_uuid}</uuid>
  <usage type='ceph'>
    <name>client.${secret_name}. secret</name>
  </usage>
</secret>
EOF
  virsh secret-define --file ${tmpsecret}
  virsh secret-set-value --secret "${secret_uuid}" --base64 "${keyring_data}"
}

CLEANUP_FILES=""

{{ if eq $security_driver "apparmor" }}
for i in $(ls -1 /etc/apparmor.d/libvirt/libvirt-* | grep -v \.files$); do
    if [[ ! -f ${i}.files ]]; then
        echo "Remove orphan profile $i"
        rm -f $i
    fi
done

# reload of vm profiles maybe needed on libvirt version change
NEW_VERSION=$(virsh --version=long && apparmor_parser --version)

if [[ -f "/var/lib/libvirt/COMPONENTS_VERSION" ]]; then
    OLD_VERSION=$(cat "/var/lib/libvirt/COMPONENTS_VERSION")
fi
if [[ "${NEW_VERSION}" != "${OLD_VERSION}" ]]; then
    vms_profiles=$(apparmor_status | grep -E '^   libvirt-\{?[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12}\}?$' || echo "")
    for prof in ${vms_profiles}; do
        if [[ -f "/etc/apparmor.d/libvirt/${prof}" ]]; then
            apparmor_parser -v -r "/etc/apparmor.d/libvirt/${prof}"
        fi
    done
    echo "${NEW_VERSION}" > "/var/lib/libvirt/COMPONENTS_VERSION"
fi
{{ end }}

if [ -n "$(cat /proc/*/comm 2>/dev/null | grep -w libvirtd)" ]; then
  set +x
  for proc in $(ls /proc/*/comm 2>/dev/null); do
    if [ "x$(cat $proc 2>/dev/null | grep -w libvirtd)" == "xlibvirtd" ]; then
      set -x
      libvirtpid=$(echo $proc | cut -f 3 -d '/')
      echo "WARNING: libvirtd daemon already running on host" 1>&2
      echo "$(cat "/proc/${libvirtpid}/status" 2>/dev/null | grep State)" 1>&2
      kill -9 "$libvirtpid" || true
      set +x
    fi
  done
  set -x
fi

rm -f /var/run/libvirtd.pid

if [[ -c /dev/kvm ]]; then
    chmod 660 /dev/kvm
    chown root:kvm /dev/kvm
fi

#Setup Cgroups to use when breaking out of Kubernetes defined groups
CGROUPS=""
for CGROUP in {{ .Values.conf.kubernetes.cgroup_controllers | include "helm-toolkit.utils.joinListWithSpace"  }}; do
  if [ -d /sys/fs/cgroup/${CGROUP} ] || grep -w $CGROUP /sys/fs/cgroup/cgroup.controllers; then
    CGROUPS+="${CGROUP},"
  fi
done
cgcreate -g ${CGROUPS%,}:/osh-libvirt

# We assume that if hugepage count > 0, then hugepages should be exposed to libvirt/qemu
hp_count="$(cat /proc/meminfo | grep HugePages_Total | tr -cd '[:digit:]')"
if [ 0"$hp_count" -gt 0 ]; then

  echo "INFO: Detected hugepage count of '$hp_count'. Enabling hugepage settings for libvirt/qemu."

  # Enable KVM hugepages for QEMU
  if [ -n "$(grep KVM_HUGEPAGES=0 /etc/default/qemu-kvm)" ]; then
    sed -i 's/.*KVM_HUGEPAGES=0.*/KVM_HUGEPAGES=1/g' /etc/default/qemu-kvm
  else
    echo KVM_HUGEPAGES=1 >> /etc/default/qemu-kvm
  fi

  # Ensure that the hugepage mount location is available/mapped inside the
  # container. This assumes use of the default ubuntu dev-hugepages.mount
  # systemd unit which mounts hugepages at this location.
  if [ ! -d /dev/hugepages ]; then
    echo "ERROR: Hugepages configured in kernel, but libvirtd container cannot access /dev/hugepages"
    exit 1
  fi
fi

if [[ "true" == "{{ .Values.conf.ceph.enabled }}" && -n "{{ .Values.conf.ceph.keyrings.cinder.secret_uuid }}" ]]; then
  #NOTE(portdirect): run libvirtd as a transient unit on the host with the osh-libvirt cgroups applied.
  cgexec -g ${CGROUPS%,}:/osh-libvirt systemd-run --scope --slice=system libvirtd --listen &

  # Wait for the libvirtd is up
  TIMEOUT=60
  while [[ ! -f /var/run/libvirtd.pid ]]; do
    if [[ ${TIMEOUT} -gt 0 ]]; then
      let TIMEOUT-=1
      sleep 1
    else
      echo "ERROR: libvirt did not start in time (pid file missing)"
      exit 1
    fi
  done

  # Even though we see the pid file the socket immediately (this is
  # needed for virsh)
  TIMEOUT=10
  while [[ ! -e /var/run/libvirt/libvirt-sock ]]; do
    if [[ ${TIMEOUT} -gt 0 ]]; then
      let TIMEOUT-=1
      sleep 1
    else
      echo "ERROR: libvirt did not start in time (socket missing)"
      exit 1
    fi
  done

    {{- range $keyring_name, $keyring_data := .Values.conf.ceph.keyrings }}
  ensure_ceph_secret "{{ $keyring_name }}" "{{ $keyring_data.secret_uuid }}" "{{ $keyring_data.key }}"
    {{- end }}

  function cleanup {
      for tmpfile in $CLEANUP_FILES; do
        rm -f $tmpfile
      done
  }
  trap cleanup EXIT

  # rejoin libvirtd
  wait
else
  #NOTE(portdirect): run libvirtd as a transient unit on the host with the osh-libvirt cgroups applied.
  exec cgexec -g ${CGROUPS%,}:/osh-libvirt systemd-run --scope --slice=system libvirtd --listen
fi
