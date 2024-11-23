#!/bin/bash
set -e

# This enables the usage of 'ovs-appctl' from neutron pod
OVS_PID=$(cat /run/openvswitch/ovs-vswitchd.pid)
OVS_CTL=/run/openvswitch/ovs-vswitchd.${OVS_PID}.ctl
OVS_SOCKET=/run/openvswitch/db.sock

chown neutron: -R {{ .Values.conf.neutron.DEFAULT.state_path }}
chown neutron: ${OVS_CTL}
chown neutron: ${OVS_SOCKET}

ovs-vsctl -t 10 list Open_vSwitch

{{- if .Values.conf.ovs_dpdk.enabled }}
# logic is replicated from openvswitch readiness probe
! /usr/bin/ovs-vsctl list Open_vSwitch | grep -q dpdk_initialized.*false
{{- end }}

ovs-appctl -t ${OVS_CTL} bond/list

# set inactivity probe for the OVS manager
{{- if .Values.conf.plugins.openvswitch_agent.ovs.of_inactivity_probe }}
MANAGER_NAME=$(ovs-vsctl get-manager)
if [[ -n "${MANAGER_NAME}" ]]; then
  ovs-vsctl set manager ${MANAGER_NAME} inactivity_probe={{ .Values.conf.plugins.openvswitch_agent.ovs.of_inactivity_probe | mul 1000 }}
fi
{{- end }}
