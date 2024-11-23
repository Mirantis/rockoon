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
CLUSTER_SIZE={{ .Values.pod.replicas.ovn_db | quote }}
PEER_PREFIX_NAME="openvswitch-ovn-db"
SERVICE_NAME="ovn-discovery"
NAMESPACE={{  .Release.Namespace }}
INTERNAL_DOMAIN="cluster.local"
DB_TYPE=${DB_TYPE}
DB_PORT=${DB_PORT}
RAFT_PORT=${RAFT_PORT}

function get_remotes {
    local remotes=""
    for i in $(seq 0 $(( $CLUSTER_SIZE - 1 ))); do
        if [[ "$remotes" != "" ]]; then
            remotes="$remotes,${PEER_PREFIX_NAME}-${i}.${SERVICE_NAME}.${NAMESPACE}.svc.${INTERNAL_DOMAIN}"
        else
            remotes="${PEER_PREFIX_NAME}-${i}.${SERVICE_NAME}.${NAMESPACE}.svc.${INTERNAL_DOMAIN}"
        fi
    done
    echo $remotes
}

DB_NAME="OVN_Northbound"

if [[ "${DB_TYPE}" == "sb" ]]; then
    DB_NAME="OVN_Southbound"
fi

function start () {

    CLUSTER_OPTS=""
    if [[ "${CLUSTER_SIZE}" -gt 1 ]]; then
        CLUSTER_OPTS="--db-${DB_TYPE}-election-timer=10000 --db-${DB_TYPE}-cluster-local-proto=tcp --db-${DB_TYPE}-cluster-local-addr=${HOSTNAME}.${SERVICE_NAME}.${NAMESPACE}.svc.${INTERNAL_DOMAIN} --db-${DB_TYPE}-cluster-local-port=${RAFT_PORT}"
    fi

    OPTS=""
    if [[ "${HOSTNAME}" != "openvswitch-ovn-db-0" ]]; then
        OPTS="$OPTS --db-${DB_TYPE}-cluster-remote-proto=tcp --db-${DB_TYPE}-cluster-remote-addr=${PEER_PREFIX_NAME}-0.${SERVICE_NAME}.${NAMESPACE}.svc.${INTERNAL_DOMAIN} --db-${DB_TYPE}-cluster-remote-port=${RAFT_PORT}"

    fi
    /usr/share/ovn/scripts/ovn-ctl \
        run_${DB_TYPE}_ovsdb \
        ${CLUSTER_OPTS} \
        --ovn-northd-sb-db=tcp:$(get_remotes) \
        ${OPTS} \
        --ovn-${DB_TYPE}-log="-vconsole:info -vfile:off" \
        -- --remote ptcp:${DB_PORT}

}

function stop () {
    /usr/share/ovn/scripts/ovn-ctl stop_${DB_TYPE}_ovsdb
}

$COMMAND
