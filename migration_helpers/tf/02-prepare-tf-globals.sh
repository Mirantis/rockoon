#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)

TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common

function generate_contrail_globals {
    # Cassandra external addresses
    local mcp2_tf_cassandra_config_0_host=$(get_mcp2_tf_external_ip tf-cassandra-config-dc1-rack1-0-external)
    local mcp2_tf_cassandra_config_1_host=$(get_mcp2_tf_external_ip tf-cassandra-config-dc1-rack1-1-external)
    local mcp2_tf_cassandra_config_2_host=$(get_mcp2_tf_external_ip tf-cassandra-config-dc1-rack1-2-external)
    local mcp2_tf_cassandra_analytics_0_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-0-external)
    local mcp2_tf_cassandra_analytics_1_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-1-external)
    local mcp2_tf_cassandra_analytics_2_host=$(get_mcp2_tf_external_ip tf-cassandra-analytics-dc1-rack1-2-external)
    # Zookeeper external addresses
    local mcp2_tf_zookeeper_client_host=$(get_mcp2_tf_external_ip tf-zookeeper-client-external)
    local mcp2_tf_zookeeper_nal_client_host=$(get_mcp2_tf_external_ip tf-zookeeper-nal-client-external)
    # Kafka external addresses
    local mcp2_tf_kafka_0_host=$(get_mcp2_tf_external_ip tf-kafka-0-external)
    local mcp2_tf_kafka_1_host=$(get_mcp2_tf_external_ip tf-kafka-1-external)
    local mcp2_tf_kafka_2_host=$(get_mcp2_tf_external_ip tf-kafka-2-external)
    # RabbitMQ Tf
    local mcp2_tf_amqp_host=$(get_mcp2_tf_external_ip amqp-external)
    cat <<EOF > model/cluster/migration/tf.yml
parameters:
  linux:
    network:
      host:
        mcp2_tf_cassandra_config_0_host:
          address: ${mcp2_tf_cassandra_config_0_host}
          names:
          - tf-cassandra-config-dc1-rack1-0-external
        mcp2_tf_cassandra_config_1_host:
          address: ${mcp2_tf_cassandra_config_1_host}
          names:
          - tf-cassandra-config-dc1-rack1-1-external
        mcp2_tf_cassandra_config_2_host:
          address: ${mcp2_tf_cassandra_config_2_host}
          names:
          - tf-cassandra-config-dc1-rack1-2-external
        mcp2_tf_cassandra_analytics_0_host:
          address: ${mcp2_tf_cassandra_analytics_0_host}
          names:
          - tf-cassandra-analytics-dc1-rack1-0-external
        mcp2_tf_cassandra_analytics_1_host:
          address: ${mcp2_tf_cassandra_analytics_1_host}
          names:
          - tf-cassandra-analytics-dc1-rack1-1-external
        mcp2_tf_cassandra_analytics_2_host:
          address: ${mcp2_tf_cassandra_analytics_2_host}
          names:
          - tf-cassandra-analytics-dc1-rack1-2-external
        mcp2_tf_zookeeper_client_host:
          address: ${mcp2_tf_zookeeper_client_host}
          names:
          - tf-zookeeper-client-external
        mcp2_tf_zookeeper_nal_client_host:
          address: ${mcp2_tf_zookeeper_nal_client_host}
          names:
          - tf-zookeeper-nal-client-external
        mcp2_tf_kafka_0_host:
          address: ${mcp2_tf_kafka_0_host}
          names:
          - tf-kafka-0-external
        mcp2_tf_kafka_1_host:
          address: ${mcp2_tf_kafka_1_host}
          names:
          - tf-kafka-1-external
        mcp2_tf_kafka_2_host:
          address: ${mcp2_tf_kafka_2_host}
          names:
          - tf-kafka-2-external
        mcp2_tf_amqp_host:
          address: ${mcp2_tf_amqp_host}
          names:
          - amqp-external
EOF
}

generate_contrail_globals

info "Globals are located in $TOP_DIR/model/cluster/migration/tf.yml please include them to $SAL_CLUSTER_ROOT/infra/init.yml"