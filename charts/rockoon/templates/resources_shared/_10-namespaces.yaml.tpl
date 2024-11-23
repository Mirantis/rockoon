---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.tf.sharedNamespace }}
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.tf.createSharedNamespace }}"create"{{ else }}"wait"{{ end }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.stacklight.sharedNamespace }}
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.stacklight.createSharedNamespace }}"create"{{ else }}"wait"{{ end }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.osdpl.settings.raw.OSCTL_REDIS_NAMESPACE }}
# NOTE(vsaienko): create shared namespace to make sure roles and
# rolebindings can be created succesfully. The kopfpeerings and
# shared namespace will be created by ceph operator by default.
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.ceph.cephSharedNamespace }}
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.ceph.createSharedNamespace }}"create"{{ else }}"wait"{{ end }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.osdpl.namespace }}
---
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Values.external_topics.sharedNamespace }}
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.external_topics.createSharedNamespace }}"create"{{ else }}"wait"{{ end }}
