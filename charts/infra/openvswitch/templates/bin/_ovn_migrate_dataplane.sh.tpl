#!/bin/bash

# Script restores original OVN integration bridge
# and bridge mappings. Also it prepares bridges
# to be used by OVN.

set -ex

trap err_trap EXIT
function err_trap {
    local r=$?
    if [[ $r -ne 0 ]]; then
        echo "${0##*/} FAILED"
    fi
    exit $r
}

OVN_BRIDGE="br-int"

echo "Getting original OVN_BRIDGE_MAPPINGS"
OVN_BRIDGE_MAPPINGS=$(ovs-vsctl get Open_vSwitch . external_ids:ovn-bridge-mappings-back | sed 's/\"//g')
if [[ -n $OVN_BRIDGE_MAPPINGS ]]; then
    echo "Setting external_ids:ovn-bridge-mappings to ${OVN_BRIDGE_MAPPINGS}"
    ovs-vsctl set Open_vSwitch . external_ids:ovn-bridge-mappings="${OVN_BRIDGE_MAPPINGS}"
fi

echo "Unset protocols on integration bridge ${OVN_BRIDGE}"
ovs-vsctl set Bridge ${OVN_BRIDGE} protocols=[]

echo "Processing bridge mappings"
for bm in ${OVN_BRIDGE_MAPPINGS//,/ }; do
  # Get bridge from string physnet:bridge
  bridge=${bm#*:}
  echo "Processing bridge ${bridge}"
  # Usually when bridge is under neutron agent control it has controller
  if [[ -n $(ovs-vsctl get-controller $bridge) ]]; then
      echo "Clearing flows and deleting controller for bridge ${bridge}"
      #!!!downtime starts when bridge is set to standalone as all flows are cleaned!!!
      ovs-vsctl set-fail-mode $bridge standalone
      ovs-vsctl set Bridge $bridge protocols=[]
      ovs-vsctl del-controller $bridge
      # Removing patch ports connecting integration and physical bridges (ovn creates its own patches)
      ovs-vsctl --if-exists del-port ${OVN_BRIDGE} int-$bridge
      ovs-vsctl --if-exists del-port $bridge phy-$bridge
  fi
done

echo "Migrating integration bridge ${OVN_BRIDGE} to OVN"
ovs-vsctl del-controller ${OVN_BRIDGE}
ovs-vsctl set Open_vSwitch . external_ids:ovn-bridge=${OVN_BRIDGE}

# Remove manager settings from db, to avoid address already in-use errors
ovs-vsctl del-manager
ovs-vsctl remove Open_Vswitch . external-ids ovn-bridge-mappings-back