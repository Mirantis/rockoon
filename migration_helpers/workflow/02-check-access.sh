#!/bin/bash

set -e #x
RUN_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$( cd $(dirname $RUN_DIR/../../) && pwd)

. $TOP_DIR/globals
. $TOP_DIR/functions-common


function check_salt {
  info "Checking salt connection"
  timeout 30 salt-call test.ping > /dev/null || die $LINENO "Failed to check salt connection"
  info "Salt connection is: OK"
}

function check_k8s {
  info "Checking access to k8s"
  if [[ ! -f $KUBECONFIG ]]; then
    die $LINENO "Kubeconfig not found"
  fi

  kubectl get namespaces > /dev/null || die "$LINENO" "Failed to get namespaces."
  info "Access to k8s is: OK"
}

function check_packages {
  info "Checking dependencies"
  dpkg -l |grep -w jq > /dev/null || die $LINENO "JQ not installed"
  info "Dependencies are: OK"
}

check_salt
check_k8s
check_packages
