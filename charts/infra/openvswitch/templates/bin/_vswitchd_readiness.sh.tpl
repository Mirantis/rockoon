#!/bin/bash
set -ex

SUPPORT_SYNC_STATE={{ .Values.conf.neutron.DEFAULT.support_sync_ovs_info | toString | lower}}
STATE_FILE={{ .Values.conf.neutron.DEFAULT.state_path }}/ovs/sync_state

ovs-appctl bond/list

if [[ "${SUPPORT_SYNC_STATE}" == "true" ]]; then

    if [[ ! -f ${STATE_FILE} ]]; then
        echo "The sync file ${STATE_FILE} not found."
        exit 1
    fi

    SYNC_STATE=$(cat ${STATE_FILE})

    if [[ ${SYNC_STATE} != "ready" ]]; then
        echo "Neutron agent hasn't synced yet, SYNC_STATE is ${SYNC_STATE}"
        exit 1
    fi
fi
