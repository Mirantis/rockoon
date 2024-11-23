#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

function check_fernets_are_disabled_mcp1 {
  info "MCP1: Checking fernet keys are disabled"
  if [[ "$(salt -C 'I@keystone:server:role:primary' pillar.items linux:system:job:keystone_fernet_rotate_rsync:enabled --timeout=60 --out json | jq '.[]|.[]')" -ne "false" ]]; then
    die $LINENO "Keystone rotation is still enabled"
  fi
  local out=$(salt -C 'I@keystone:server:role:primary' cmd.run  "sudo -u keystone crontab -l || true")
  if echo "$out" |grep -q "Lines below here are managed by Salt"; then
    if echo "$out |grep fernet"; then
      die $LINENO "The cron for keystone user are still present."
    fi
  fi

  info "MCP1: Rotation is disabled."
}

function check_fernets_are_disabled_mcp2 {
  info "MCP2: Checking fernet keys are disabled"
  for key_type in credential fernet; do
    kubectl -n openstack get cronjobs 2>&1|grep "keystone-${key_type}-rotate" -q && die $LINENO "MCP2: rotation is enabled for $key_type"
  done
  info "MCP2: Rotation is disabled."
}

function force_remove_cron_for_keystone {
  info "Removing crons for keystone"
  salt -C 'I@keystone:server' cmd.run 'sudo -u keystone crontab -r || true'
  info "Removed keystone cronjobs."
}



#refresh_pillars
force_remove_cron_for_keystone
check_fernets_are_disabled_mcp1
check_fernets_are_disabled_mcp2
