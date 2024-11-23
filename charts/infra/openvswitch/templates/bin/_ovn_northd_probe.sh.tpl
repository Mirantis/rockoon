#!/bin/bash
set -ex

OVN_NORTHD_PROCESS_NAME="ovn-northd"
OVN_SB_PORT=$1
OVN_NB_PORT=$2

for port in $OVN_SB_PORT $OVN_NB_PORT; do
  if ! ss -plan --tcp |grep -w ${OVN_NORTHD_PROCESS_NAME} |grep -e ${port} |grep -e ESTAB -e SYN-SENT; then
    echo "No ESTABLISHED or SYN-SENT TCP connections found for ${OVN_NORTHD_PROCESS_NAME} and ${port}"
  fi
done
