#!/bin/bash
set -ex
chown -R {{ .Values.pod.security_context.openvswitch_ovn_controller.pod.runAsUser }} /var/lib/ovn
chown -R {{ .Values.pod.security_context.openvswitch_ovn_controller.container.db.runAsUser }} /run/openvswitch
