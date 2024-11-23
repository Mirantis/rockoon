apiVersion: v1
data:
kind: ConfigMap
data:
  extra_conf.ini: |
    [maintenance]
    respect_nova_az = false
metadata:
  name: rockoon-config
  namespace: {{ .Release.Namespace }}
  annotations:
    # NOTE(vsaienko): do not update resource if exist to avoid config loose
    "openstackdeployments.lcm.mirantis.com/skip_update": "true"
