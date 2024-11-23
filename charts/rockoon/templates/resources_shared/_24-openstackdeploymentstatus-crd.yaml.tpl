apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: openstackdeploymentstatus.lcm.mirantis.com
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
              type: object
            status:
              x-kubernetes-preserve-unknown-fields: true
              type: object
              description: this is arbitrary JSON
              properties:
                services:
                  type: object
                  properties:
                    alarming: &component_status
                      type: object
                      properties:
                        state:
                          type: string
                          description: >
                            The current state of LCM operation one of WAITING, APPLYING or APPLIED.
                        release:
                          description: The MOSK release version.
                          type: string
                        openstack_version:
                          type: string
                          description: >
                            The current OpenStack version of component.
                        controller_version:
                          type: string
                          description: >
                            The version of openstack controller that handling changes.
                        fingerprint:
                          type: string
                          description: >
                            The related osdpl object hash summ.
                        changes:
                          type: string
                          description: >
                            Last handled changes applied to release. Reserved for future.
                        cause:
                          type: string
                          description: The event cause.
                        timestamp:
                          type: string
                          description: >
                            The timestamp of latest state change operation.
                        tasks:
                          type: array
                          description:
                            List of tasks performed with service.
                          items:
                            type: object
                            properties:
                              description:
                                type: string
                                description: Task description
                              start_time:
                                type: string
                                description: The start time of the task
                    baremetal: *component_status
                    block-storage: *component_status
                    cloudprober: *component_status
                    compute: *component_status
                    coordination: *component_status
                    dashboard: *component_status
                    database: *component_status
                    dns: *component_status
                    event: *component_status
                    identity: *component_status
                    image: *component_status
                    ingress: *component_status
                    instance-ha: *component_status
                    key-manager: *component_status
                    load-balancer: *component_status
                    memcached: *component_status
                    messaging: *component_status
                    metering: *component_status
                    metric: *component_status
                    networking: *component_status
                    object-storage: *component_status
                    orchestration: *component_status
                    placement: *component_status
                    redis: *component_status
                    stepler: *component_status
                    tempest: *component_status
                    dynamic-resource-balancer: *component_status
                osdpl:
                    type: object
                    properties:
                      state:
                        type: string
                        description: >
                          The overall state of LCM operation related to openstackdeployment changes of APPLYING or APPLIED.
                          APPLYING is set when not all tasks related to LCM are completed. APPLIED is set when all tasks
                          from LCM are completed.
                      openstack_version:
                        type: string
                        description: >
                          The current OpenStack version.
                      changes:
                        type: string
                        description: >
                          The string representation of changes of osdpl object.
                      cause:
                        type: string
                        description: The event cause
                      fingerprint:
                        type: string
                        description: >
                          The hash summ of osdpl object spec handled by LCM.
                      controller_version:
                        type: string
                        description: >
                          The version of openstack controller that handle osdpl object.
                      release:
                        description: The MOSK release version.
                        type: string
                      timestamp:
                        type: string
                        description: >
                          The timestamp of latest state change operation.
                      health:
                        description: |
                          The overal health of OpenStack deployment. Represents as
                          <num Ready>/<total number> of components. Component treated
                          as unhealthy when at least 1 replica is notReady.
                        type: string
                      lcm_progress:
                        description: |
                          The LCM progress of OpenStack Deployment. Is a string with X/Y,
                          where X - is the number of deployed applications (k8s objects applied)
                          and Y is the total number of applications we manage.
                        type: string
                health:
                  type: object
                  x-kubernetes-preserve-unknown-fields: true
      additionalPrinterColumns:
      - name: OpenStack Version
        type: string
        description: OpenStack release
        jsonPath: .status.osdpl.openstack_version
      - name: Controller Version
        type: string
        jsonPath: .status.osdpl.controller_version
      - name: State
        type: string
        jsonPath: .status.osdpl.state
      - jsonPath: .status.osdpl.lcm_progress
        name: LCM Progress
        type: string
      - jsonPath: .status.osdpl.health
        name: HEALTH
        type: string
      - name: MOSK Release
        type: string
        jsonPath: .status.osdpl.release
  # either Namespaced or Cluster
  scope: Namespaced
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: openstackdeploymentstatus
    # singular name to be used as an alias on the CLI and for display
    singular: openstackdeploymentstatus
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: OpenStackDeploymentStatus
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
      - osdplst
    categories:
      - all
