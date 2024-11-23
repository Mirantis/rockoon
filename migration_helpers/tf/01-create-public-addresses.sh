#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common



function expose_mcp2_3d_party_services {
cat << EOF | kubectl -n tf apply -f -
---
apiVersion: v1
kind: Service
metadata:
  name: tf-kafka-0-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: kafka
    port: 9092
    protocol: TCP
    targetPort: 9092
  selector:
    statefulset.kubernetes.io/pod-name: tf-kafka-0
---
apiVersion: v1
kind: Service
metadata:
  name: tf-kafka-1-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: kafka
    port: 9092
    protocol: TCP
    targetPort: 9092
  selector:
    statefulset.kubernetes.io/pod-name: tf-kafka-1
---
apiVersion: v1
kind: Service
metadata:
  name: tf-kafka-2-external
  namespace: tf
spec:
  type: LoadBalancer
  ports:
  - name: kafka
    port: 9092
    protocol: TCP
    targetPort: 9092
  selector:
    statefulset.kubernetes.io/pod-name: tf-kafka-2
---
apiVersion: v1
kind: Service
metadata:
  name: tf-zookeeper-nal-client-external
spec:
  type: LoadBalancer
  ports:
  - name: tcp-client
    port: 2181
    protocol: TCP
    targetPort: 2181
  selector:
    app: tf-zookeeper-nal
---
apiVersion: v1
kind: Service
metadata:
  name: tf-zookeeper-client-external
spec:
  type: LoadBalancer
  ports:
  - name: tcp-client
    port: 2181
    protocol: TCP
    targetPort: 2181
  selector:
    app: tf-zookeeper
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-config-dc1-rack1-0-external
spec:
  type: LoadBalancer
  ports:
    - port: 9160
      name: thrift
      protocol: TCP
    - port: 9042
      name: cql
      protocol: TCP
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-config-dc1-rack1-0
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-config-dc1-rack1-1-external
spec:
  type: LoadBalancer
  ports:
    - port: 9160
      name: thrift
      protocol: TCP
    - port: 9042
      name: cql
      protocol: TCP
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-config-dc1-rack1-1
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-config-dc1-rack1-2-external
spec:
  type: LoadBalancer
  ports:
    - port: 9160
      name: thrift
      protocol: TCP
    - port: 9042
      name: cql
      protocol: TCP
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-config-dc1-rack1-2
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-analytics-dc1-rack1-2-external
spec:
  type: LoadBalancer
  ports:
  - name: cql
    port: 9042
    protocol: TCP
    targetPort: 9042
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-analytics-dc1-rack1-2
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-analytics-dc1-rack1-1-external
spec:
  type: LoadBalancer
  ports:
  - name: cql
    port: 9042
    protocol: TCP
    targetPort: 9042
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-analytics-dc1-rack1-1
---
apiVersion: v1
kind: Service
metadata:
  name: tf-cassandra-analytics-dc1-rack1-0-external
spec:
  type: LoadBalancer
  ports:
  - name: cql
    port: 9042
    protocol: TCP
    targetPort: 9042
  selector:
    statefulset.kubernetes.io/pod-name: tf-cassandra-analytics-dc1-rack1-0
---
apiVersion: v1
kind: Service
metadata:
  name: amqp-external
spec:
  type: LoadBalancer
  ports:
  - name: http
    port: 15672
    protocol: TCP
    targetPort: 15672
  - name: amqp
    port: 5672
    protocol: TCP
    targetPort: 5672
  selector:
    app: rabbitmq
EOF
}

expose_mcp2_3d_party_services