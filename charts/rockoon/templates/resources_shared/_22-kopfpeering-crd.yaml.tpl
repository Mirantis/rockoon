---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterkopfpeerings.zalando.org
spec:
  scope: Cluster
  group: zalando.org
  names:
    kind: ClusterKopfPeering
    plural: clusterkopfpeerings
    singular: clusterkopfpeering
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            status:
              type: object
              x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: kopfpeerings.zalando.org
spec:
  scope: Namespaced
  group: zalando.org
  names:
    kind: KopfPeering
    plural: kopfpeerings
    singular: kopfpeering
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            status:
              type: object
              x-kubernetes-preserve-unknown-fields: true
