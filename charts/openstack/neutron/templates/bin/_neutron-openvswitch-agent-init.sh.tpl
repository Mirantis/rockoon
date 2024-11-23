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

OVS_SOCKET=/run/openvswitch/db.sock
OVS_PID=$(cat /run/openvswitch/ovs-vswitchd.pid)
OVS_CTL=/run/openvswitch/ovs-vswitchd.${OVS_PID}.ctl

function get_dpdk_config_value {
  values=$1
  filter=$2
  value=$(echo ${values} | jq -r ${filter})
  if [[ "${value}" == "null" ]]; then
    echo ""
  else
    echo "${value}"
  fi
}

DPDK_CONFIG_FILE=/tmp/dpdk.conf
DPDK_CONFIG=""
DPDK_ENABLED=false
if [ -f ${DPDK_CONFIG_FILE} ]; then
  DPDK_CONFIG=$(cat ${DPDK_CONFIG_FILE})
  if [[ $(get_dpdk_config_value ${DPDK_CONFIG} '.enabled') == "true" ]]; then
    DPDK_ENABLED=true
  fi
fi

function bind_nic {
  echo $2 > /sys/bus/pci/devices/$1/driver_override
  echo $1 > /sys/bus/pci/drivers/$2/bind
}

function unbind_nic {
  echo $1 > /sys/bus/pci/drivers/$2/unbind
  echo > /sys/bus/pci/devices/$1/driver_override
}

function get_name_by_pci_id {
  path=$(find /sys/bus/pci/devices/$1/ -name net)
  if [ -n "${path}" ] ; then
    echo $(ls -1 $path/)
  fi
}

function get_ip_address_from_interface {
  local interface=$1
  local ip=$(ip -4 -o addr s "${interface}" | awk '{ print $4; exit }' | awk -F '/' '{print $1}')
  if [ -z "${ip}" ] ; then
    exit 1
  fi
  echo ${ip}
}

function get_ip_prefix_from_interface {
  local interface=$1
  local prefix=$(ip -4 -o addr s "${interface}" | awk '{ print $4; exit }' | awk -F '/' '{print $2}')
  if [ -z "${prefix}" ] ; then
    exit 1
  fi
  echo ${prefix}
}

function assign_ip {
  local interface=$1
  local ip_address=$2

  if ! ip -o addr show dev "$interface" | grep -q "$ip_address"; then
      echo "The ip address $ip_address is not present on inerface $interface. Adding it"
      ip addr flush dev $interface
      ip addr add $ip_address dev $interface
  else
      echo "IP address $ip_address is present on interface $interface"
  fi
}

function get_pf_or_vf_pci {
  dpdk_pci_id=${1}
  vf_index=${2}

  if [ -n "$vf_index" ]
  then
    iface=$(get_name_by_pci_id "${dpdk_pci_id}")
    sysfs_numvfs_path="/sys/class/net/${iface}/device/sriov_numvfs"
    if [[ -f /sys/class/net/${iface}/device/sriov_numvfs &&
          "$(cat /sys/class/net/${iface}/device/sriov_numvfs)" -ne "0" &&
          -e /sys/class/net/${iface}/device/virtfn${vf_index} ]]
    then
      dpdk_pci_id=$(ls -la /sys/class/net/${iface}/device/virtfn${vf_index})
      dpdk_pci_id=${dpdk_pci_id#*"../"}
    else
      echo "Error fetching the VF PCI for PF: ["${iface}", "${dpdk_pci_id}"] and VF-Index: ${vf_index}."
      exit 1
    fi
  fi
}

function bind_dpdk_nic {
  target_driver=${1}
  pci_id=${2}

  current_driver="$(get_driver_by_address "${pci_id}" )"
  if [ "$current_driver" != "$target_driver" ]; then
    if [ "$current_driver" != "" ]; then
      unbind_nic "${pci_id}" ${current_driver}
    fi
    bind_nic "${pci_id}" ${target_driver}
  fi
}

function process_dpdk_nics {
  target_driver=$(get_dpdk_config_value ${DPDK_CONFIG} '.driver')
  # loop over all nics
  echo $DPDK_CONFIG | jq -r -c '.nics[]' | \
  while IFS= read -r nic; do
    local port_name=$(get_dpdk_config_value ${nic} '.name')
    local pci_id=$(get_dpdk_config_value ${nic} '.pci_id')
    local bridge=$(get_dpdk_config_value ${nic} '.bridge')
    local vf_index=$(get_dpdk_config_value ${nic} '.vf_index')

    iface=$(get_name_by_pci_id "${pci_id}")

    if [ -n "${iface}" ]; then
      ip link set ${iface} promisc on
      if [ -n "${vf_index}" ]; then
        vf_string="vf ${vf_index}"
        ip link set ${iface} ${vf_string} trust on

        # NOTE: To ensure proper toggle of spoofchk,
        # turn it on then off.
        ip link set ${iface} ${vf_string} spoofchk on
        ip link set ${iface} ${vf_string} spoofchk off
      fi
    fi

    # Fetch the PCI to be bound to DPDK driver.
    # In case VF Index is configured then PCI of that particular VF
    # is bound to DPDK, otherwise PF PCI is bound to DPDK.
    get_pf_or_vf_pci "${pci_id}" "${vf_index}"

    bind_dpdk_nic ${target_driver} "${dpdk_pci_id}"

    dpdk_options=""
    ofport_request=$(get_dpdk_config_value ${nic} '.ofport_request')
    if [ -n "${ofport_request}" ]; then
      dpdk_options+='ofport_request=${ofport_request} '
    fi
    n_rxq=$(get_dpdk_config_value ${nic} '.n_rxq')
    if [ -n "${n_rxq}" ]; then
      dpdk_options+='options:n_rxq=${n_rxq} '
    fi
    n_txq=$(get_dpdk_config_value ${nic} '.n_txq')
    if [ -n "${n_txq}" ]; then
      dpdk_options+='options:n_txq=${n_txq} '
    fi
    pmd_rxq_affinity=$(get_dpdk_config_value ${nic} '.pmd_rxq_affinity')
    if [ -n "${pmd_rxq_affinity}" ]; then
      dpdk_options+='other_config:pmd-rxq-affinity=${pmd_rxq_affinity} '
    fi
    mtu=$(get_dpdk_config_value ${nic} '.mtu')
    if [ -n "${mtu}" ]; then
      dpdk_options+='mtu_request=${mtu} '
    fi
    n_rxq_size=$(get_dpdk_config_value ${nic} '.n_rxq_size')
    if [ -n "${n_rxq_size}" ]; then
      dpdk_options+='options:n_rxq_desc=${n_rxq_size} '
    fi
    n_txq_size=$(get_dpdk_config_value ${nic} '.n_txq_size')
    if [ -n "${n_txq_size}" ]; then
      dpdk_options+='options:n_txq_desc=${n_txq_size} '
    fi
    vhost_iommu_support=$(get_dpdk_config_value ${nic} '.vhost-iommu-support')
    if [ -n "${vhost_iommu_support}" ]; then
      dpdk_options+='options:vhost-iommu-support=${vhost_iommu_support} '
    fi

    ovs-vsctl --db=unix:${OVS_SOCKET} --may-exist add-port ${bridge} ${port_name} \
       -- set Interface ${port_name} type=dpdk options:dpdk-devargs=${pci_id} ${dpdk_options}

  done
}

function process_dpdk_bonds {
  target_driver=$(get_dpdk_config_value ${DPDK_CONFIG} '.driver')
  # loop over all bonds
  echo $DPDK_CONFIG | jq -r -c '.bonds[]' > /tmp/bonds_array
  while IFS= read -r bond; do
    local bond_name=$(get_dpdk_config_value ${bond} '.name')
    local dpdk_bridge=$(get_dpdk_config_value ${bond} '.bridge')
    local mtu=$(get_dpdk_config_value ${bond} '.mtu')
    local n_rxq=$(get_dpdk_config_value ${bond} '.n_rxq')
    local n_txq=$(get_dpdk_config_value ${bond} '.n_txq')
    local ofport_request=$(get_dpdk_config_value ${bond} '.ofport_request')
    local n_rxq_size=$(get_dpdk_config_value ${bond} '.n_rxq_size')
    local n_txq_size=$(get_dpdk_config_value ${bond} '.n_txq_size')
    local vhost_iommu_support=$(get_dpdk_config_value ${bond} '.vhost-iommu-support')
    local ovs_options=$(get_dpdk_config_value ${bond} '.ovs_options')

    local nic_name_str=""
    local dev_args_str=""

    echo $bond | jq -r -c '.nics[]' > /tmp/nics_array
    while IFS= read -r nic; do
      local pci_id=$(get_dpdk_config_value ${nic} '.pci_id')
      local nic_name=$(get_dpdk_config_value ${nic} '.name')
      local pmd_rxq_affinity=$(get_dpdk_config_value ${nic} '.pmd_rxq_affinity')
      local vf_index=$(get_dpdk_config_value ${nic} '.vf_index')
      local vf_string=""

      iface=$(get_name_by_pci_id "${pci_id}")

      if [ -n "${iface}" ]; then
        ip link set ${iface} promisc on
        if [ -n "${vf_index}" ]; then
          vf_string="vf ${vf_index}"
          ip link set ${iface} ${vf_string} trust on

          # NOTE: To ensure proper toggle of spoofchk,
          # turn it on then off.
          ip link set ${iface} ${vf_string} spoofchk on
          ip link set ${iface} ${vf_string} spoofchk off
        fi
      fi

      # Fetch the PCI to be bound to DPDK driver.
      # In case VF Index is configured then PCI of that particular VF
      # is bound to DPDK, otherwise PF PCI is bound to DPDK.
      get_pf_or_vf_pci "${pci_id}" "${vf_index}"

      bind_dpdk_nic ${target_driver} "${dpdk_pci_id}"

      nic_name_str+=" "${nic_name}""
      dev_args_str+=" -- set Interface "${nic_name}" type=dpdk options:dpdk-devargs=""${dpdk_pci_id}"

      if [[ -n ${mtu} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" mtu_request=${mtu}"
      fi

      if [[ -n ${n_rxq} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" options:n_rxq=${n_rxq}"
      fi

      if [[ -n ${n_txq} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" options:n_txq=${n_txq}"
      fi

      if [[ -n ${ofport_request} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" ofport_request=${ofport_request}"
      fi

      if [[ -n ${pmd_rxq_affinity} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" other_config:pmd-rxq-affinity=${pmd_rxq_affinity}"
      fi

      if [[ -n ${n_rxq_size} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" options:n_rxq_desc=${n_rxq_size}"
      fi

      if [[ -n ${n_txq_size} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" options:n_txq_desc=${n_txq_size}"
      fi

      if [[ -n ${vhost_iommu_support} ]]; then
        dev_args_str+=" -- set Interface "${nic_name}" options:vhost-iommu-support=${vhost_iommu_support}"
      fi
    done < /tmp/nics_array

    ovs-vsctl --db=unix:${OVS_SOCKET} --may-exist add-bond "${dpdk_bridge}" "${bond_name}" \
      ${nic_name_str} ${ovs_options} ${dev_args_str}
  done < "/tmp/bonds_array"
}

function set_dpdk_module_log_level {
  # loop over all target modules
  if [ -n "$(get_dpdk_config_value ${DPDK_CONFIG} '.modules')" ]; then
    echo $DPDK_CONFIG | jq -r -c '.modules[]' > /tmp/modules_array
    while IFS= read -r module; do
      local mod_name=$(get_dpdk_config_value ${module} '.name')
      local mod_level=$(get_dpdk_config_value ${module} '.log_level')

      ovs-appctl -t ${OVS_CTL} vlog/set ${mod_name}:${mod_level}
      ovs-appctl -t ${OVS_CTL} vlog/list|grep ${mod_name}
    done < /tmp/modules_array
  fi
}

function get_driver_by_address {
  if [[ -e /sys/bus/pci/devices/$1/driver ]]; then
    echo $(ls /sys/bus/pci/devices/$1/driver -al | awk '{n=split($NF,a,"/"); print a[n]}')
  fi
}

function init_ovs_dpdk_bridge {
  bridge=$1
  ovs-vsctl --db=unix:${OVS_SOCKET} --may-exist add-br ${bridge} \
  -- set Bridge ${bridge} datapath_type=netdev
  ip link set ${bridge} up
}

# create all additional bridges defined in the DPDK section
function init_ovs_dpdk_bridges {
  local br
  echo $DPDK_CONFIG | jq -r -c '.bridges[]' | \
  while IFS= read -r bridge_config; do
    br=$(get_dpdk_config_value $bridge_config '.name')
    init_ovs_dpdk_bridge ${br}
    ip_address=$(get_dpdk_config_value ${bridge_config} '.ip_address')
    if [[ "$ip_address" != "null" ]]; then
        assign_ip "$br" "$ip_address"
    fi
  done
}

# handle any bridge mappings
# /tmp/auto_bridge_add is one line json file: {"br-ex1":"eth1","br-ex2":"eth2"}
for bmap in `sed 's/[{}"]//g' /tmp/auto_bridge_add | tr "," "\n"`
do
  bridge=${bmap%:*}
  iface=${bmap#*:}
  ovs-vsctl --no-wait --may-exist add-br $bridge
  if [ -n "$iface" ] && [ "$iface" != "null" ]
  then
    ovs-vsctl --no-wait --may-exist add-port $bridge $iface
    if [[ $(get_dpdk_config_value ${DPDK_CONFIG} '.enabled') != "true" ]]; then
      ip link set dev $iface up
    fi
  fi
done

function init_ovs_interfaces {
  # Generic function to init abstract interfaces in OVS
  for bridge_name in $(cat /tmp/ovs_interfaces.json  | jq -r -c '. | keys[] as $k | "\($k)"'); do
     local bridge_opts=$(cat /tmp/ovs_interfaces.json  | jq --arg bridge_name "$bridge_name" -r -c '.[$bridge_name]')
     ovs-vsctl --no-wait --may-exist add-br $bridge_name
     for nic in $(echo $bridge_opts | jq -r -c '.nics[]'); do
        local nic_name=$(get_dpdk_config_value $nic '.name')
        local ovs_opts=""
        for opt in $(get_dpdk_config_value $nic '.interface_options' | jq -r '. |keys[] as $k | "\($k)=\(.[$k])"'); do
            ovs_opts="$ovs_opts -- set Interface $nic_name $opt "
        done
        ovs-vsctl --no-wait --may-exist add-port $bridge_name $nic_name $ovs_opts
     done
  done
}
init_ovs_interfaces

tunnel_types="{{- .Values.conf.plugins.openvswitch_agent.agent.tunnel_types -}}"
if [[ -n "${tunnel_types}" ]] ; then
    tunnel_interface="{{- .Values.network.interface.tunnel -}}"
    if [ -z "${tunnel_interface}" ] ; then
        # search for interface with tunnel network routing
        tunnel_network_cidr="{{- .Values.network.interface.tunnel_network_cidr -}}"
        if [ -z "${tunnel_network_cidr}" ] ; then
            tunnel_network_cidr="0/0"
        fi
        # If there is not tunnel network gateway, exit
        tunnel_interface=$(ip -4 route list ${tunnel_network_cidr} | awk -F 'dev' '{ print $2; exit }' \
            | awk '{ print $1 }') || exit 1
    fi
fi

if [[ "${DPDK_ENABLED}" == "true" ]]; then
  init_ovs_dpdk_bridges
  process_dpdk_nics
  process_dpdk_bonds
  set_dpdk_module_log_level
fi

# determine local-ip dynamically based on interface provided but only if tunnel_types is not null
if [[ -n "${tunnel_types}" ]] ; then
  LOCAL_IP=$(get_ip_address_from_interface ${tunnel_interface})
  if [ -z "${LOCAL_IP}" ] ; then
    echo "Var LOCAL_IP is empty"
    exit 1
  fi

tee > /tmp/pod-shared/ml2-local-ip.ini << EOF
[ovs]
local_ip = "${LOCAL_IP}"
EOF

  if [[ "${DPDK_ENABLED}" == "true" ]]; then
    PREFIX=$(get_ip_prefix_from_interface "${tunnel_interface}")

    # loop over all nics
    echo $DPDK_CONFIG | jq -r -c '.bridges[]' | \
    while IFS= read -r br; do
      bridge_name=$(get_dpdk_config_value ${br} '.name')
      tunnel_underlay_vlan=$(get_dpdk_config_value ${br} '.tunnel_underlay_vlan')

      if [[ "${bridge_name}" == "${tunnel_interface}" ]]; then
        # Route the tunnel traffic via the physical bridge
        if [[ -n "${LOCAL_IP}" && -n "${PREFIX}" ]]; then
          if [[ -n $(ovs-appctl -t ${OVS_CTL} ovs/route/show | grep "${LOCAL_IP}" | grep -v '^Cached:') ]]; then
            ovs-appctl -t ${OVS_CTL} ovs/route/del "${LOCAL_IP}"/"${PREFIX}"
          fi
          ovs-appctl -t ${OVS_CTL} ovs/route/add "${LOCAL_IP}"/"${PREFIX}" "${tunnel_interface}"

          if [[ -n "${tunnel_underlay_vlan}" ]]; then
            # If there is not tunnel network gateway, exit
            IFS=. read -r i1 i2 i3 i4 <<< "${LOCAL_IP}"
            IFS=. read -r xx m1 m2 m3 m4 <<< $(for a in $(seq 1 32); do if [ $(((a - 1) % 8)) -eq 0 ]; then echo -n .; fi; if [ $a -le ${PREFIX} ]; then echo -n 1; else echo -n 0; fi; done)
            tunnel_network_cidr=$(printf "%d.%d.%d.%d\n" "$((i1 & (2#$m1)))" "$((i2 & (2#$m2)))" "$((i3 & (2#$m3)))" "$((i4 & (2#$m4)))") || exit 1
            # Put a new flow to tag all the tunnel traffic with configured vlan-id
            if [[ -n $(ovs-ofctl dump-flows "${tunnel_interface}" | grep "nw_dst=${tunnel_network_cidr}") ]]; then
              ovs-ofctl del-flows "${tunnel_interface}" "cookie=0x9999/-1, table=0, ip,nw_dst=${tunnel_network_cidr}"
            fi
            ovs-ofctl add-flow "${tunnel_interface}" "cookie=0x9999, table=0, priority=8, ip,nw_dst=${tunnel_network_cidr}, actions=mod_vlan_vid:${tunnel_underlay_vlan},NORMAL"
          fi
        fi
        break
      fi
    done
  fi
fi

{{- if and ( empty .Values.conf.neutron.DEFAULT.host ) ( .Values.pod.use_fqdn.neutron_agent ) }}
mkdir -p /tmp/pod-shared
tee > /tmp/pod-shared/neutron-agent.ini << EOF
[DEFAULT]
host = $(hostname --fqdn)
EOF
{{- end }}
