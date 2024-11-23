#!/bin/bash

set -e #x

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

SALTFORMULA_DIR=${SALTFORMULA_DIR:-"/srv/salt/env/prd/"}

function set_public_addresses {
    cat << EOF | kubectl -n tf apply -f -
---
apiVersion: v1
kind: Service
metadata:
  name: control-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: xmpp
    port: 5269
    protocol: TCP
    targetPort: 5269
  selector:
    app: tf-control
---
apiVersion: v1
kind: Service
metadata:
  name: dns-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: dns
    port: 53
    protocol: TCP
    targetPort: 53
  selector:
    app: tf-control
EOF
}

function map_vrouter_agents {
  local CONTROL="$(get_mcp2_tf_external_ip "control-external"):5269"
  local DNS="$(get_mcp2_tf_external_ip "dns-external"):53"

  local CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-vrouter-agent.conf"
  echo "MANUAL ACTION REQUIRED"
  echo "Update $CONFIG_FILENAME set servers in section [DNS] to $DNS, in section [CONTROL-NODE] to $CONTROL"

}
set_public_addresses

map_vrouter_agents