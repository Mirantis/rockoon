#!/bin/bash -e
#
# THIS FILE IS GOING TO BE EXECUTED ON ANY CFG NODES (MCP1).
#
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

MASTER_CP_NODE=$(salt -C 'I@keystone:server:role:primary' grains.get fqdn --out newline_values_only)
CACHE_DIR="/var/cache/salt/master/minions/${MASTER_CP_NODE}/files/var/lib/keystone"
for key_dir in ${KEY_REPOSITORY}; do
    salt $MASTER_CP_NODE cp.push_dir $key_dir
    key_type=$(basename ${key_dir} | cut -d- -f1)
    mv ${CACHE_DIR}/${key_type}-{keys,data}
    kubectl delete secret keystone-${key_type}-data -n openstack
    kubectl create secret generic keystone-${key_type}-data --from-file=${CACHE_DIR}/${key_type}-data -n openstack || die $LINENO "Failed to update keys: keystone-${key_type}"
done

function restart_keystone_api {
    info "Restarting keystone-api on MCP2"
    kubectl delete pods -l application=keystone,component=api -n openstack || die $LINENO "Failed to restart keystone api"
    info "Keystone API was restarted"
}

restart_keystone_api
