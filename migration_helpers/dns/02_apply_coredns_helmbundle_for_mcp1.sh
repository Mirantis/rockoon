#/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

kubectl create ns ${COREDNS_NS} || true
kubectl apply -f ${COREDNS_HELMBUNDLE_CR}
