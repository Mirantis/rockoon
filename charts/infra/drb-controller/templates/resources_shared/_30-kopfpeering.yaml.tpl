---
apiVersion: zalando.org/v1
kind: ClusterKopfPeering
metadata:
  name: drb-controller
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Release.Namespace }}"
  name: drb-controller.drb-controller
