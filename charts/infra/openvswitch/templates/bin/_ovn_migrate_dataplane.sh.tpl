#!/bin/bash

# Script restores original OVN integration bridge
# and bridge mappings. Also it prepares bridges
# to be used by OVN.

set -ex
COMMAND="${@:-start}"

OVN_BRIDGE="br-int"
OVS_DB_SOCK="/run/openvswitch/db.sock"
OVN_CONTROLLER_PID="/run/openvswitch/ovn-controller.pid"

trap err_trap EXIT
function err_trap {
    local r=$?
    if [[ $r -ne 0 ]]; then
        echo "${0##*/} FAILED"
    fi
    exit $r
}


function start () {

    declare -a PORTS_REMOVE_ARGS=()
    for i in $(ovs-vsctl list interface | awk '/name[ ]*: qr-|ha-|qg-|rfp-|sg-|fg-/ { print $3 }'); do
        PORTS_REMOVE_ARGS+=("-- --if-exists del-port $i");
    done
    PORTS_REMOVE_NUM=${#PORTS_REMOVE_ARGS[@]}

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

    # Clean migration bridges now to avoid issues with ovn controller
    # stuck in port binding of duplicated ports
    ovs-vsctl --if-exists del-br br-tun
    echo "Remove tunnel and migration bridges"
    ovs-vsctl --if-exists del-br br-migration
    ovs-vsctl --if-exists del-port br-int patch-tun
    echo "Cleaning all migration fake bridges"
    for br in $(egrep '^migbr-' <(ovs-vsctl list-br)); do
        ovs-vsctl del-br $br
    done

    # need to remove old ports to avoid ip address conflicts with neutron ports
    echo "Found ${PORTS_REMOVE_NUM} Neutron OVS ports to remove"
    if [[ ${PORTS_REMOVE_NUM} -gt 0 ]]; then
        echo "Started removing Neutron OVS ports"
        ovs-vsctl ${PORTS_REMOVE_ARGS[@]}
        echo "Finished removing Neutron OVS ports"
    fi

    # Running ovn controller in background, later additional migration steps
    # will be added
    /usr/bin/ovn-controller unix:${OVS_DB_SOCK} \
    -vconsole:emer \
    -vconsole:err \
    -vconsole:info \
    --pidfile=${OVN_CONTROLLER_PID} &

    # Remove manager settings from db, to avoid address already in-use errors
    ovs-vsctl del-manager
    # Removing if backup of mapping should be always the last step
    # in the procedure as it is checked by readiness probe
    ovs-vsctl remove Open_Vswitch . external-ids ovn-bridge-mappings-back
    sleep infinity
}

function ready () {
    /tmp/ovn_controller_readiness.sh

    if ovs-vsctl --no-wait get Open_vSwitch . external_ids:ovn-bridge-mappings-back; then
        echo "Dataplane migration is not completed yet"
        exit 1
    fi
}

$COMMAND