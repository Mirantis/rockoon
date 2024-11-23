#!/bin/bash

set -ex
curl 0.0.0.0:{{ tuple "network" "internal" "api" . | include "helm-toolkit.endpoints.endpoint_port_lookup" }}

{{- if ( has "ovn" .Values.network.backend ) }}
python /tmp/generic-health-probe.py \
--process-name neutron-server \
--check k8s_svc_ip_change \
--k8s-svcs {{ tuple "ovn_db" "internal" . | include "helm-toolkit.endpoints.endpoint_host_lookup" }} \
--probe-type liveness
{{- end }}
