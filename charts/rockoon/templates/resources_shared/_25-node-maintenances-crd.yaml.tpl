---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: clustermaintenancerequests.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: ClusterMaintenanceRequest
    listKind: ClusterMaintenanceRequestList
    plural: clustermaintenancerequests
    singular: clustermaintenancerequest
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: |-
              APIVersion defines the versioned schema of this representation of an object.
              Servers should convert recognized schemas to the latest internal value, and
              may reject unrecognized values.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
            type: string
          kind:
            description: |-
              Kind is a string value representing the REST resource this object represents.
              Servers may infer this from the endpoint the client submits requests to.
              Cannot be updated.
              In CamelCase.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
            type: string
          metadata:
            type: object
          spec:
            properties:
              release:
                type: string
              scope:
                enum:
                - os
                - drain
                type: string
            type: object
        type: object
    served: true
    storage: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: clusterworkloadlocks.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: ClusterWorkloadLock
    listKind: ClusterWorkloadLockList
    plural: clusterworkloadlocks
    singular: clusterworkloadlock
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: |-
              APIVersion defines the versioned schema of this representation of an object.
              Servers should convert recognized schemas to the latest internal value, and
              may reject unrecognized values.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
            type: string
          kind:
            description: |-
              Kind is a string value representing the REST resource this object represents.
              Servers may infer this from the endpoint the client submits requests to.
              Cannot be updated.
              In CamelCase.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
            type: string
          metadata:
            type: object
          spec:
            properties:
              controllerName:
                type: string
            required:
            - controllerName
            type: object
          status:
            properties:
              errorMessage:
                type: string
              inactivationProgress:
                properties:
                  description:
                    type: string
                  percentage:
                    maximum: 100
                    type: integer
                type: object
              release:
                type: string
              state:
                enum:
                - inactive
                - active
                - failed
                type: string
              statusObjectReference:
                description: |-
                  ObjectReference contains enough information to let you inspect or modify the referred object.
                  ---
                  New uses of this type are discouraged because of difficulty describing its usage when embedded in APIs.
                   1. Ignored fields.  It includes many fields which are not generally honored.  For instance, ResourceVersion and FieldPath are both very rarely valid in actual usage.
                   2. Invalid usage help.  It is impossible to add specific help for individual usage.  In most embedded usages, there are particular
                      restrictions like, "must refer only to types A and B" or "UID not honored" or "name must be restricted".
                      Those cannot be well described when embedded.
                   3. Inconsistent validation.  Because the usages are different, the validation rules are different by usage, which makes it hard for users to predict what will happen.
                   4. The fields are both imprecise and overly precise.  Kind is not a precise mapping to a URL. This can produce ambiguity
                      during interpretation and require a REST mapping.  In most cases, the dependency is on the group,resource tuple
                      and the version of the actual struct is irrelevant.
                   5. We cannot easily change it.  Because this type is embedded in many locations, updates to this type
                      will affect numerous schemas.  Don't make new APIs embed an underspecified API type they do not control.

                  Instead of using this type, create a locally provided and used type that is well-focused on your reference.
                  For example, ServiceReferences for admission registration: https://github.com/kubernetes/api/blob/release-1.17/admissionregistration/v1/types.go#L533 .
                properties:
                  apiVersion:
                    description: API version of the referent.
                    type: string
                  fieldPath:
                    description: |-
                      If referring to a piece of an object instead of an entire object, this string
                      should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
                      For example, if the object reference is to a container within a pod, this would take on a value like:
                      "spec.containers{name}" (where "name" refers to the name of the container that triggered
                      the event) or if no container name is specified "spec.containers[2]" (container with
                      index 2 in this pod). This syntax is chosen only to have some well-defined way of
                      referencing a part of an object.
                      TODO: this design is not final and this field is subject to change in the future.
                    type: string
                  kind:
                    description: |-
                      Kind of the referent.
                      More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
                    type: string
                  name:
                    description: |-
                      Name of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
                    type: string
                  namespace:
                    description: |-
                      Namespace of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
                    type: string
                  resourceVersion:
                    description: |-
                      Specific resourceVersion to which this reference is made, if any.
                      More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
                    type: string
                  uid:
                    description: |-
                      UID of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
                    type: string
                type: object
                x-kubernetes-map-type: atomic
            required:
            - state
            type: object
        type: object
    served: true
    storage: true
    subresources:
      status: {}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: nodemaintenancerequests.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: NodeMaintenanceRequest
    listKind: NodeMaintenanceRequestList
    plural: nodemaintenancerequests
    singular: nodemaintenancerequest
  scope: Cluster
  versions:

  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: |-
              APIVersion defines the versioned schema of this representation of an object.
              Servers should convert recognized schemas to the latest internal value, and
              may reject unrecognized values.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
            type: string
          kind:
            description: |-
              Kind is a string value representing the REST resource this object represents.
              Servers may infer this from the endpoint the client submits requests to.
              Cannot be updated.
              In CamelCase.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
            type: string
          metadata:
            type: object
          spec:
            properties:
              nodeName:
                type: string
              release:
                type: string
              scope:
                enum:
                - os
                - drain
                type: string
            required:
            - nodeName
            type: object
        type: object
    served: true
    storage: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: nodeworkloadlocks.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: NodeWorkloadLock
    listKind: NodeWorkloadLockList
    plural: nodeworkloadlocks
    singular: nodeworkloadlock
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: |-
              APIVersion defines the versioned schema of this representation of an object.
              Servers should convert recognized schemas to the latest internal value, and
              may reject unrecognized values.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
            type: string
          kind:
            description: |-
              Kind is a string value representing the REST resource this object represents.
              Servers may infer this from the endpoint the client submits requests to.
              Cannot be updated.
              In CamelCase.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
            type: string
          metadata:
            type: object
          spec:
            properties:
              controllerName:
                type: string
              nodeDeletionRequestSupported:
                type: boolean
              nodeName:
                type: string
            required:
            - controllerName
            - nodeName
            type: object
          status:
            properties:
              errorMessage:
                type: string
              inactivationProgress:
                properties:
                  description:
                    type: string
                  percentage:
                    maximum: 100
                    type: integer
                type: object
              release:
                type: string
              state:
                enum:
                - inactive
                - active
                - failed
                type: string
              statusObjectReference:
                description: |-
                  ObjectReference contains enough information to let you inspect or modify the referred object.
                  ---
                  New uses of this type are discouraged because of difficulty describing its usage when embedded in APIs.
                   1. Ignored fields.  It includes many fields which are not generally honored.  For instance, ResourceVersion and FieldPath are both very rarely valid in actual usage.
                   2. Invalid usage help.  It is impossible to add specific help for individual usage.  In most embedded usages, there are particular
                      restrictions like, "must refer only to types A and B" or "UID not honored" or "name must be restricted".
                      Those cannot be well described when embedded.
                   3. Inconsistent validation.  Because the usages are different, the validation rules are different by usage, which makes it hard for users to predict what will happen.
                   4. The fields are both imprecise and overly precise.  Kind is not a precise mapping to a URL. This can produce ambiguity
                      during interpretation and require a REST mapping.  In most cases, the dependency is on the group,resource tuple
                      and the version of the actual struct is irrelevant.
                   5. We cannot easily change it.  Because this type is embedded in many locations, updates to this type
                      will affect numerous schemas.  Don't make new APIs embed an underspecified API type they do not control.

                  Instead of using this type, create a locally provided and used type that is well-focused on your reference.
                  For example, ServiceReferences for admission registration: https://github.com/kubernetes/api/blob/release-1.17/admissionregistration/v1/types.go#L533 .
                properties:
                  apiVersion:
                    description: API version of the referent.
                    type: string
                  fieldPath:
                    description: |-
                      If referring to a piece of an object instead of an entire object, this string
                      should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
                      For example, if the object reference is to a container within a pod, this would take on a value like:
                      "spec.containers{name}" (where "name" refers to the name of the container that triggered
                      the event) or if no container name is specified "spec.containers[2]" (container with
                      index 2 in this pod). This syntax is chosen only to have some well-defined way of
                      referencing a part of an object.
                      TODO: this design is not final and this field is subject to change in the future.
                    type: string
                  kind:
                    description: |-
                      Kind of the referent.
                      More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
                    type: string
                  name:
                    description: |-
                      Name of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
                    type: string
                  namespace:
                    description: |-
                      Namespace of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
                    type: string
                  resourceVersion:
                    description: |-
                      Specific resourceVersion to which this reference is made, if any.
                      More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
                    type: string
                  uid:
                    description: |-
                      UID of the referent.
                      More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
                    type: string
                type: object
                x-kubernetes-map-type: atomic
            required:
            - state
            type: object
        type: object
    served: true
    storage: true
    subresources:
      status: {}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: nodedisablenotifications.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: NodeDisableNotification
    listKind: NodeDisableNotificationList
    plural: nodedisablenotifications
    singular: nodedisablenotification
  preserveUnknownFields: false
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            properties:
              nodeName:
                type: string
            required:
            - nodeName
            type: object
        type: object
    served: true
    storage: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    "openstackdeployments.lcm.mirantis.com/shared_resource_action": {{ if .Values.node_maintenance.create_crd }}"create"{{ else }}"wait"{{ end }}
    controller-gen.kubebuilder.io/version: v0.14.0
  name: nodedeletionrequests.lcm.mirantis.com
spec:
  group: lcm.mirantis.com
  names:
    kind: NodeDeletionRequest
    listKind: NodeDeletionRequestList
    plural: nodedeletionrequests
    singular: nodedeletionrequest
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: |-
              APIVersion defines the versioned schema of this representation of an object.
              Servers should convert recognized schemas to the latest internal value, and
              may reject unrecognized values.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
            type: string
          kind:
            description: |-
              Kind is a string value representing the REST resource this object represents.
              Servers may infer this from the endpoint the client submits requests to.
              Cannot be updated.
              In CamelCase.
              More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
            type: string
          metadata:
            type: object
          spec:
            properties:
              nodeName:
                type: string
            required:
            - nodeName
            type: object
        type: object
    served: true
    storage: true
