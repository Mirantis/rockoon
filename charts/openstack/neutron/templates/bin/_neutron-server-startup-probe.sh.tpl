#!/bin/bash

{{- if ( has "ovn" .Values.network.backend ) }}
python /tmp/health-probe.py \
--process-name neutron-server \
--probe-type startup \
--check ovn_maintenance \
--config-file /etc/neutron/neutron.conf
{{- end }}
