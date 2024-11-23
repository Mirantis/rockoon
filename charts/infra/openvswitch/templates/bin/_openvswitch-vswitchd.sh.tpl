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
COMMAND="${@:-start}"

OVS_SOCKET=/run/openvswitch/db.sock
OVS_PID=/run/openvswitch/ovs-vswitchd.pid

# Create vhostuser directory and grant nova user (default UID 42424) access
# permissions.
{{- if .Values.conf.ovs_dpdk.enabled }}
mkdir -p /run/openvswitch/{{ .Values.conf.ovs_dpdk.vhostuser_socket_dir }}
chown {{ .Values.pod.user.nova.uid }}.{{ .Values.pod.user.nova.uid }} /run/openvswitch/{{ .Values.conf.ovs_dpdk.vhostuser_socket_dir }}
{{- end }}

function start () {
  while [[ ! -e "${OVS_SOCKET}" ]] ; do
      echo "waiting for ovs socket $sock"
      sleep 5
  done

  ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait show

{{- range $option, $value := .Values.conf.ovs_other_config }}
  {{- if $value }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:{{ $option }}={{ $value }}
  {{- end }}
{{- end }}

{{- if .Values.conf.ovs_dpdk.enabled }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:dpdk-hugepage-dir={{ .Values.conf.ovs_dpdk.hugepages_mountpath | quote }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:dpdk-socket-mem={{ .Values.conf.ovs_dpdk.socket_memory | quote }}

{{- if .Values.conf.ovs_dpdk.mem_channels }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:dpdk-mem-channels={{ .Values.conf.ovs_dpdk.mem_channels | quote }}
{{- end }}

{{- if hasKey .Values.conf.ovs_dpdk "pmd_cpu_mask" }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:pmd-cpu-mask={{ .Values.conf.ovs_dpdk.pmd_cpu_mask | quote }}
    PMD_CPU_MASK={{ .Values.conf.ovs_dpdk.pmd_cpu_mask | quote }}
{{- end }}

{{- if hasKey .Values.conf.ovs_dpdk "lcore_mask" }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:dpdk-lcore-mask={{ .Values.conf.ovs_dpdk.lcore_mask | quote }}
    LCORE_MASK={{ .Values.conf.ovs_dpdk.lcore_mask | quote }}
{{- end }}

{{- if hasKey .Values.conf.ovs_dpdk "vhost_iommu_support" }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:vhost-iommu-support={{ .Values.conf.ovs_dpdk.vhost_iommu_support }}
{{- end }}

    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:vhost-sock-dir={{ .Values.conf.ovs_dpdk.vhostuser_socket_dir | quote }}
    ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait set Open_vSwitch . other_config:dpdk-init=true

  # No need to create the cgroup if lcore_mask or pmd_cpu_mask is not set.
  if [[ -n ${PMD_CPU_MASK} || -n ${LCORE_MASK} ]]; then
      # Setup Cgroups to use when breaking out of Kubernetes defined groups
      mkdir -p /sys/fs/cgroup/cpuset/osh-openvswitch
      target_mems="/sys/fs/cgroup/cpuset/osh-openvswitch/cpuset.mems"
      target_cpus="/sys/fs/cgroup/cpuset/osh-openvswitch/cpuset.cpus"

      # Ensure the write target for the for cpuset.mem for the pod exists
      if [[ -f "$target_mems" && -f "$target_cpus" ]]; then
        # Write cpuset.mem and cpuset.cpus for new cgroup and add current task to new cgroup
        cat /sys/fs/cgroup/cpuset/cpuset.mems > "$target_mems"
        cat /sys/fs/cgroup/cpuset/cpuset.cpus > "$target_cpus"
        echo $$ > /sys/fs/cgroup/cpuset/osh-openvswitch/tasks
      else
        echo "ERROR: Could not find write target for either cpuset.mems: $target_mems or cpuset.cpus: $target_cpus"
      fi
  fi
{{- end }}

  {{- if .Values.conf.neutron.DEFAULT.support_sync_ovs_info }}
  OVS_SYNC_STATE={{ .Values.conf.neutron.DEFAULT.state_path }}/ovs/sync_state
  rm -f ${OVS_SYNC_STATE}
  {{- end }}

  function get_config_value {
    values=$1
    filter=$2
    value=$(echo ${values} | jq -r ${filter})
    if [[ "${value}" == "null" ]]; then
      echo ""
    else
      echo "${value}"
    fi
  }
  function init_ovs_interfaces {
    # Generic function to init abstract interfaces in OVS
    for bridge_name in $(cat /tmp/ovs_interfaces.json  | jq -r -c '. | keys[] as $k | "\($k)"'); do
       local bridge_opts=$(cat /tmp/ovs_interfaces.json  | jq --arg bridge_name "$bridge_name" -r -c '.[$bridge_name]')
       ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait --may-exist add-br $bridge_name
       for nic in $(echo $bridge_opts | jq -r -c '.nics[]'); do
          local nic_name=$(get_config_value $nic '.name')
          local ovs_opts=""
          for opt in $(get_config_value $nic '.interface_options' | jq -r '. |keys[] as $k | "\($k)=\(.[$k])"'); do
              ovs_opts="$ovs_opts -- set Interface $nic_name $opt "
          done
          ovs-vsctl --db=unix:${OVS_SOCKET} --no-wait --may-exist add-port $bridge_name $nic_name $ovs_opts
       done
    done
  }
  init_ovs_interfaces

  exec /usr/sbin/ovs-vswitchd unix:${OVS_SOCKET} \
          --pidfile=${OVS_PID} {{ .Values.pod.cmd.startup.ovs_vswitchd.ovs_vswitchd.cmd_args }}
}

function stop () {
  PID=$(cat $OVS_PID)
  ovs-appctl -T1 -t /run/openvswitch/ovs-vswitchd.${PID}.ctl exit
}

function poststart () {
  # This enables the usage of 'ovs-appctl' from neutron-ovs-agent pod.
  while [[ ! -e "$OVS_PID" ]]; do
      echo "Waiting $OVS_PID"
      sleep 1
  done
  PID=$(cat $OVS_PID)
  OVS_CTL=/run/openvswitch/ovs-vswitchd.${PID}.ctl
  while [[ ! -e "$OVS_CTL" ]]; do
      echo "Waiting $OVS_CTL"
      sleep 1
  done
  chown {{ .Values.pod.user.nova.uid }}.{{ .Values.pod.user.nova.uid }} ${OVS_CTL}
}

$COMMAND
