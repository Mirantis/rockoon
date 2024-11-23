#!/bin/bash -e
#
# THIS FILE IS GOING TO BE EXECUTED ON ANY CFG NODES (MCP1).
#
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function update_ceph_keyrings {
    local salt_out
    local keyring_dir='/etc/ceph/'
    local temp=$(mktemp -d)
    local live_rgw=$(get_first_active_minion -C "I@ceph:radosgw")
    local live_cmn=$(get_first_active_minion -C '"I@ceph:common:keyring:admin and I@ceph:mon"')
    local live_ctl=$(get_first_active_minion -C "I@cinder:controller")
    local live_cmp=$(get_first_active_minion -C "I@nova:compute")
    salt "$live_cmn" cmd.run "cat ${keyring_dir}/ceph.client.cinder.keyring | grep 'key =' | sed 's/key =/client.cinder;/g'" --out newline_values_only > $temp/cinder
    salt "$live_cmn" cmd.run "cat ${keyring_dir}/ceph.client.nova.keyring | grep 'key =' | sed 's/key =/client.nova;/g'" --out newline_values_only > $temp/nova;
    salt "$live_cmn" cmd.run "cat ${keyring_dir}/ceph.client.glance.keyring | grep 'key =' | sed 's/key =/client.glance;/g'" --out newline_values_only > $temp/glance;

    local backup_pool=$(salt "$live_ctl" pillar.get cinder:volume:backup:ceph_pool --out newline_values_only)
    salt "$live_cmn" cmd.run "echo \";$backup_pool:backup:hdd\"" --out newline_values_only >> $temp/cinder

    local nova_pool=$(salt "$live_cmp" pillar.get nova:compute:ceph:rbd_pool --out newline_values_only)
    salt "$live_cmn" cmd.run "echo \";$nova_pool:ephemeral:hdd\"" --out newline_values_only >> $temp/nova

    local glance_pool=$(salt "$live_ctl" pillar.get glance:server:storage:pool --out newline_values_only)
    echo ";$glance_pool:images:hdd" >> $temp/glance
    sed -i "s/^;/;$glance_pool:images:hdd;/" $temp/nova
    sed -i "s/^;/;$glance_pool:images:hdd;/" $temp/cinder

    local backends_map=$(salt $(get_first_active_minion -C I@cinder:volume) pillar.items cinder:volume:backend --out=json | jq '.[]|."cinder:volume:backend"')
    echo "${backends_map}"
    if [ "${backends_map}" == '{}' ]; then
        backends_map=$(salt $(get_first_active_minion -C I@cinder:controller) pillar.items cinder:controller:backend --out=json | jq '.[]|."cinder:controller:backend"')
    fi
    echo "${backends_map}" | jq -r 'to_entries | .[] | if .value.engine == "ceph" then .value.pool else {} end' | \
    while read -r line; do
        if [ ${line} != '{}' ]; then
            sed -i "s/^;/;${line}:volumes:hdd;/" $temp/cinder
            sed -i "s/^;/;${line}:volumes:hdd;/" $temp/nova
        fi
    done

    salt "$live_cmn" cmd.run "cat ${keyring_dir}/ceph.client.admin.keyring | grep 'key =' | sed 's/key =//g'" --out newline_values_only > $temp/client.admin
    salt "$live_cmn" cmd.run "cat ${keyring_dir}/ceph.conf | grep 'mon host' | grep -oE 'mon host = (\b([0-9]{1,3}\.){3}[0-9]{1,3}\b:\b([0-9]{4}),){2}\b([0-9]{1,3}\.){3}[0-9]{1,3}\b:\b[0-9]{4}' | sed 's/mon host = //g'" --out newline_values_only > $temp/mon_endpoints

    salt "$live_rgw" cmd.run "cat ${keyring_dir}/ceph.client.rgw.rgw*.keyring | grep 'key =' | sed 's/key =//g' | tail -n 1" --out newline_values_only > $temp/rgw_external
    salt "$live_rgw" cmd.run "cat ${keyring_dir}/ceph.client.rgw.rgw*.keyring | grep 'key =' | sed 's/key =//g' | tail -n 1" --out newline_values_only > $temp/rgw_internal

    sed -r 's/\s+//g' -i ${temp}/*
    truncate -s -1 file ${temp}/*

    kubectl delete secret openstack-ceph-keys -n openstack-ceph-shared || info "Secret doesn't exists"
    kubectl create secret generic openstack-ceph-keys --from-file=${temp}/ -n openstack-ceph-shared || die $LINENO "Failed to update ceph keyrings"
    info "Ceph keyrings were updated successfully"
}

update_ceph_keyrings
