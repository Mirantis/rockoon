#!/bin/bash

{{- if ( has "ovn" .Values.network.backend ) }}
# skip probe when API runs via uwsgi.
if [ -z "$(type -p neutron-server || true)" ]; then
  exit 0
fi
python /tmp/health-probe.py \
--process-name neutron-server \
--probe-type startup \
--check ovn_maintenance \
--config-file /etc/neutron/neutron.conf
{{- end }}
