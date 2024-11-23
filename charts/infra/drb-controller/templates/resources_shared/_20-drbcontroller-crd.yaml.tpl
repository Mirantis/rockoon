---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: drbconfigs.lcm.mirantis.com
spec:
  # group name to use for REST API: /apis/<group>/<version>
  group: lcm.mirantis.com
  # list of versions supported by this CustomResourceDefinition
  versions:
    - name: v1alpha1
      # Each version can be enabled/disabled by Served flag.
      served: true
      # One and only one version must be marked as the storage version.
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            apiVersion:
              type: string
            kind:
              type: string
            metadata:
              type: object
            spec:
              required:
                - reconcileInterval
                - collector
                - scheduler
                - actuator
              type: object
              properties:
                migrateAny:
                  type: boolean
                  default: true
                  description: Whether any entities except tagged are migrated (default), or only tagged entities are migrated
                hosts:
                  type: array
                  description: list of hosts to apply this config, default all hosts
                  default: []
                  items:
                    type: string
                reconcileInterval:
                  type: integer
                  description: interval to run the drb reconcile loop
                collector:
                  type: object
                  description: configuration of metrics collector
                  properties:
                    name:
                      type: string
                      description: existing entrypoint from 'drb_controller.collector' namespace
                  required:
                    - name
                  x-kubernetes-preserve-unknown-fields: true
                scheduler:
                  type: object
                  description: configuration of scheduler that chooses what and where to move
                  properties:
                    name:
                      type: string
                      description: existing entrypoint from 'drb_controller.scheduler' namespace
                  required:
                    - name
                  x-kubernetes-preserve-unknown-fields: true
                actuator:
                  type: object
                  description: configuration of actuator that actually moves resources around
                  properties:
                    name:
                      type: string
                      description: existing entrypoint from 'drb_controller.actuator' namespace
                  required:
                    - name
                  x-kubernetes-preserve-unknown-fields: true
  scope: Namespaced
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: drbconfigs
    # singular name to be used as an alias on the CLI and for display
    singular: drbconfig
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: DRBConfig
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
      - drb
    categories:
      - all
