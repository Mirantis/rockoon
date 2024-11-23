---
apiVersion: zalando.org/v1
kind: ClusterKopfPeering
metadata:
  name: drb-controller
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: drb-controller.drb-controller
