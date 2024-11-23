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
  name: collector-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: collector
    port: 8086
    protocol: TCP
    targetPort: 8086
  selector:
    app: tf-analytics
---
apiVersion: v1
kind: Service
metadata:
  name: analytics-api-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: api
    port: 8081
    protocol: TCP
    targetPort: 8081
  selector:
    app: tf-analytics
EOF
}

function switch_analytics {

CONF_LIST_1=\
"${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-alarm-gen.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-analytics-api.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-api.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-control.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-device-manager.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-dns.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-query-engine.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-schema.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-snmp-collector.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-svc-monitor.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-topology.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-vrouter-agent.conf"

CONF_LIST_2=\
"${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-analytics-nodemgr.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-config-nodemgr.conf
${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-control-nodemgr.conf"

local COLLECTORS="$(get_mcp2_tf_external_ip "collector-external"):8086"
VAR="collectors"
for i in ${CONF_LIST_1}; do
  info "Updating collectors in $i"
  sed -i  "s/\($VAR *= *\).*/\1${COLLECTORS}/" ${i};
done

VAR="server_list"
for i in ${CONF_LIST_2}; do
  info "Updating collectors in $i"
  sed -i  "s/\($VAR *= *\).*/\1${COLLECTORS}/" ${i};
done

local API="$(get_mcp2_tf_external_ip "analytics-api-external"):8081"

VAR="analytics_server_list"
info "Update analytics API"
sed -i  "s/\($VAR *= *\).*/\1${API}/" "${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-svc-monitor.conf";
}

set_public_addresses

switch_analytics

refresh_pillars
info "Update opencontrail config files"
salt -C 'ntw*' state.sls opencontrail.config
salt -C 'ntw*' state.sls opencontrail.control
salt -C 'nal*' state.sls opencontrail.collector
salt -C 'cmp*' state.sls opencontrail.compute

info "Update hosts and recreate opencontrail docker containers"
salt -C 'ntw* or nal*' state.sls linux.network.host
salt -C 'ntw* or nal*' state.sls docker