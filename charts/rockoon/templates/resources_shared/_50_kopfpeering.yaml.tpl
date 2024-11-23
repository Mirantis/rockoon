---
apiVersion: zalando.org/v1
kind: ClusterKopfPeering
metadata:
  name: rockoon
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.osdpl
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.osdplstatus
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.secrets
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.health
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.node
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.nodemaintenancerequest
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.ceph.cephSharedNamespace }}"
  name: rockoon.ceph.secrets
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.osdplsecret
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.tf.sharedNamespace }}"
  name: rockoon.tf.secrets
---
apiVersion: zalando.org/v1
kind: KopfPeering
metadata:
  namespace: "{{ .Values.osdpl.namespace }}"
  name: rockoon.configmaps
