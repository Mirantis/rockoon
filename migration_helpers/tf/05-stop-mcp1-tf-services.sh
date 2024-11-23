#!/bin/bash

set -e #x

function stop_analytics {
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-collector'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-analytics-api'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-query-engine'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-alarm-gen'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-snmp-collector'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-topology'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analytics systemctl stop contrail-analytics-nodemgr'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analyticsdb systemctl stop contrail-analytics-nodemgr'
}

function stop_analyticsdb {
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-database'
salt -C 'I@opencontrail:collector' cmd.run 'doctrail analyticsdb systemctl stop contrail-database'
}

function stop_control {
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-control'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-named'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-dns'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-control-nodemgr'
}
function stop_config {
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-api*'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-schema'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-svc-monitor'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-device-manager'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-config-nodemgr'
}
function stop_webui {
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-webui'
salt -C 'I@opencontrail:control' cmd.run 'doctrail controller systemctl stop contrail-webui-middleware'
}

stop_$1