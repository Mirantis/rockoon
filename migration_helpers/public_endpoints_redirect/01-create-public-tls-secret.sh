#!/bin/bash

RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common
. $TOP_DIR/database/functions

kubectl create ns ${HELMBUNDLE_NS}

CA=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:chain --out=newline_values_only | base64 -w 0)
if [ -z "$CA" ]; then
  CA_FILE=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:chain_file --out=newline_values_only)
  CA=$(salt 'prx01*' file.read ${CA_FILE} --out=newline_values_only | base64 -w 0)
fi

CERT=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:cert --out=newline_values_only | base64 -w 0)
if [ -z "$CERT" ]; then
  CERT_FILE=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:cert_file --out=newline_values_only)
  CERT=$(salt 'prx01*' file.read ${CERT_FILE} --out=newline_values_only | base64 -w 0)
fi

KEY=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:key --out=newline_values_only | base64 -w 0)
if [ -z "$KEY" ]; then
  KEY_FILE=$(salt 'prx01*' pillar.get _param:apache_horizon_ssl:key_file --out=newline_values_only)
  KEY=$(salt 'prx01*' file.read ${KEY_FILE} --out=newline_values_only | base64 -w 0 )
fi

cat << EOF | kubectl apply -f -
apiVersion: v1
data:
  ca.crt: $CA
  tls.crt: $CERT
  tls.key: $KEY
kind: Secret
metadata:
  annotations:
  name: public-endpoints-tls
  namespace: ${FORWARDER_NS}
type: tls
EOF
