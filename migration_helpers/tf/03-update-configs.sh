#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

SALTFORMULA_DIR=${SALTFORMULA_DIR:-"/srv/salt/env/prd/"}

function get_mcp2_tf_external_ip {
    local service="$1"
    echo "$(kubectl -n tf get services $service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
}


function map_conf {


CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-alarm-gen.conf"

declare -A map_alarm_gen
map_alarm_gen=(["kafka_broker_list"]="tf-kafka-0-external:9092 tf-kafka-1-external:9092 tf-kafka-2-external:9092"
               ["zk_list"]="tf-zookeeper-nal-client-external:2181"
               ["rabbitmq_server_list"]="amqp-external:5672"
               ["rabbitmq_port"]="5672"
               ["rabbitmq_user"]="guest"
               ["rabbitmq_password"]="guest"
               ["rabbitmq_vhost"]="\/"
               )

info "Map config for $CONFIG_FILENAME"
for i in "${!map_alarm_gen[@]}"; do
  info "Set $i to ${map_alarm_gen[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_alarm_gen[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-analytics-api.conf"
declare -A map_analytics_api
map_analytics_api=(["cassandra_server_list"]="tf-cassandra-analytics-dc1-rack1-0-external:9042 tf-cassandra-analytics-dc1-rack1-1-external:9042 tf-cassandra-analytics-dc1-rack1-2-external:9042"
                   ["zk_list"]="tf-zookeeper-client-external:2181"
                   )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_analytics_api[@]}"; do
   info "Set $i to ${map_analytics_api[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_analytics_api[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-api.conf"
declare -A map_contrail_api
map_contrail_api=(["cassandra_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                  ["zk_server_ip"]="tf-zookeeper-client-external:2181"
                  ["rabbit_server"]="amqp-external"
                  ["rabbit_port"]="5672"
                  ["rabbit_user"]="guest"
                  ["rabbit_password"]="guest"
                  ["rabbit_vhost"]="\/"
                  )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_api[@]}"; do
  info "Set $i to ${map_contrail_api[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_api[$i]}/" ${CONFIG_FILENAME};
done


CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-control.conf"

declare -A map_contrail_control
map_contrail_control=(["config_db_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9042 tf-cassandra-config-dc1-rack1-1-external:9042 tf-cassandra-config-dc1-rack1-2-external:9042"
                       ["rabbitmq_server_list"]="amqp-external:5672"
                       ["rabbitmq_port"]="5672"
                       ["rabbitmq_user"]="guest"
                       ["rabbitmq_password"]="guest"
                       ["rabbitmq_vhost"]="\/"
                      )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_control[@]}"; do
  info "Set $i to ${map_contrail_control[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_control[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-device-manager.conf"

declare -A map_contrail_dev_man
map_contrail_dev_man=(["zk_server_ip"]="tf-zookeeper-client-external:2181"
                      ["cassandra_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                      ["rabbit_server"]="amqp-external"
                      ["rabbit_port"]="5672"
                      ["rabbit_user"]="guest"
                      ["rabbit_password"]="guest"
                      ["rabbit_vhost"]="\/"
                      )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_dev_man[@]}"; do
  info "Set $i to ${map_contrail_dev_man[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_dev_man[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-dns.conf"

declare -A map_contrail_dns
map_contrail_dns=(["zk_server_ip"]="tf-zookeeper-client-external:2181"
                  ["config_db_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                  ["rabbitmq_server_list"]="amqp-external:5672"
                  ["rabbitmq_port"]="5672"
                  ["rabbitmq_user"]="guest"
                  ["rabbitmq_password"]="guest"
                  ["rabbitmq_vhost"]="\/"
                 )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_dns[@]}"; do
  info "Set $i to ${map_contrail_dns[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_dns[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-query-engine.conf"

declare -A map_contrail_query
map_contrail_query=(["cassandra_server_list"]="tf-cassandra-analytics-dc1-rack1-0-external:9042 tf-cassandra-analytics-dc1-rack1-1-external:9042 tf-cassandra-analytics-dc1-rack1-2-external:9042"
                   )

info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_query[@]}"; do
  info "Set $i to ${map_contrail_query[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_query[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-schema.conf"

declare -A map_contrail_schema
map_contrail_schema=(["zk_server_ip"]="tf-zookeeper-client-external:2181"
                     ["cassandra_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                     ["rabbit_server"]="amqp-external"
                     ["rabbit_port"]="5672"
                     ["rabbit_user"]="guest"
                     ["rabbit_password"]="guest"
                     ["rabbit_vhost"]="\/"
                    )
info "Map config for $CONFIG_FILENAME"

for i in "${!map_contrail_schema[@]}"; do
  info "Set $i to ${map_contrail_schema[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_schema[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-snmp-collector.conf"

declare -A map_contrail_snmp_col
map_contrail_snmp_col=(["zookeeper"]="tf-zookeeper-client-external:2181"
                       ["config_db_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                       ["rabbitmq_server_list"]="amqp-external:5672"
                       ["rabbitmq_port"]="5672"
                       ["rabbitmq_user"]="guest"
                       ["rabbitmq_password"]="guest"
                       ["rabbitmq_vhost"]="\/"
                      )
info "Map config for $CONFIG_FILENAME"

for i in "${!map_contrail_snmp_col[@]}"; do
  info "Set $i to ${map_contrail_snmp_col[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_snmp_col[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-svc-monitor.conf"

declare -A map_contrail_svc_mon
map_contrail_svc_mon=(["zk_server_ip"]="tf-zookeeper-client-external:2181"
                      ["cassandra_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                      ["rabbit_server"]="amqp-external"
                      ["rabbit_port"]="5672"
                      ["rabbit_user"]="guest"
                      ["rabbit_password"]="guest"
                      ["rabbit_vhost"]="\/"
                      )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_svc_mon[@]}"; do
  info "Set $i to ${map_contrail_svc_mon[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_svc_mon[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-topology.conf"

declare -A map_contrail_topology
map_contrail_topology=(["zookeeper"]="tf-zookeeper-client-external:2181"
                       ["config_db_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9160 tf-cassandra-config-dc1-rack1-1-external:9160 tf-cassandra-config-dc1-rack1-2-external:9160"
                       ["rabbitmq_server_list"]="amqp-external:5672"
                       ["rabbitmq_port"]="5672"
                       ["rabbitmq_user"]="guest"
                       ["rabbitmq_password"]="guest"
                       ["rabbitmq_vhost"]="\/"
                       )
info "Map config for $CONFIG_FILENAME"

for i in "${!map_contrail_topology[@]}"; do
  info "Set $i to ${map_contrail_topology[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_topology[$i]}/" ${CONFIG_FILENAME};
done

CONFIG_FILENAME="${SALTFORMULA_DIR}opencontrail/files/4.1/contrail-collector.conf"

local mcp2_tf_cassandra_analytics_0_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-0-external)
local mcp2_tf_cassandra_analytics_1_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-1-external)
local mcp2_tf_cassandra_analytics_2_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-2-external)

declare -A map_contrail_collector
map_contrail_collector=(["kafka_broker_list"]="tf-kafka-0-external:9092 tf-kafka-1-external:9092 tf-kafka-2-external:9092"
                        ["cassandra_server_list"]="${mcp2_tf_cassandra_analytics_0_host}:9042 ${mcp2_tf_cassandra_analytics_1_host}:9042 ${mcp2_tf_cassandra_analytics_2_host}:9042"
                        ["zookeeper_server_list"]="tf-zookeeper-client-external:2181"
                        ["config_db_server_list"]="tf-cassandra-config-dc1-rack1-0-external:9042 tf-cassandra-config-dc1-rack1-1-external:9042 tf-cassandra-config-dc1-rack1-2-external:9042"
                        ["rabbitmq_server_list"]="amqp-external:5672"
                        ["rabbitmq_port"]="5672"
                        ["rabbitmq_user"]="guest"
                        ["rabbitmq_password"]="guest"
                        ["rabbitmq_vhost"]="\/"
                        )
info "Map config for $CONFIG_FILENAME"
for i in "${!map_contrail_collector[@]}"; do
  info "Set $i to ${map_contrail_collector[$i]}"
  sed -i  "s/\($i *= *\).*/\1${map_contrail_collector[$i]}/" ${CONFIG_FILENAME};
done

}

map_conf

refresh_pillars
info "Update opencontrail config files"
salt -C 'ntw*' state.sls opencontrail.config
salt -C 'ntw*' state.sls opencontrail.control
salt -C 'nal*' state.sls opencontrail.collector

info "Update hosts and recreate opencontrail docker containers"
salt -C 'ntw* or nal*' state.sls linux.network.host
salt -C 'ntw* or nal*' state.sls docker
