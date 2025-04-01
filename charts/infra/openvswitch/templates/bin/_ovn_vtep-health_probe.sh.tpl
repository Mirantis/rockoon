#!/bin/bash


OVNSB_PORT={{ tuple "ovn_db" "internal" "sb" . | include "helm-toolkit.endpoints.endpoint_port_lookup" | quote }}
OVN_VTEP_PROCESS_NAME="ovn-controller-"


ss -plant |grep ${OVN_VTEP_PROCESS_NAME} |grep ${OVNSB_PORT}
