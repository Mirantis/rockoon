apiVersion: v1
kind: Secret
data:
  clouds.yaml: Cg==
metadata:
  name: keystone-os-clouds
  namespace: {{ .Release.Namespace }}
  annotations:
    # NOTE(vsaienko): do not update resource if exist to avoid config loose
    "openstackdeployments.lcm.mirantis.com/skip_update": "true"
