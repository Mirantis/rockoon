apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: openstackdeployments.lcm.mirantis.com
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
              x-kubernetes-preserve-unknown-fields: true
              # Do all validation in python jsonschema.
            status:
              x-kubernetes-preserve-unknown-fields: true
              type: object
              description: this is arbitrary JSON
              properties:
                credentials:
                  type: object
                  properties:
                    admin:
                      type: object
                      properties:
                        rotation_id:
                          type: integer
                          description: |
                            Integer incremental field for trigerring keystone admin user credentials rotation.
                            Should be greater than 0. Increase only by one is allowed. Once added, removing
                            this field is not allowed.
                    service:
                      type: object
                      properties:
                        rotation_id:
                          type: integer
                          description: |
                            Integer incremental field for triggering service user password rotation.
                            Which includes credential rotation for OpenStack services to mysql/rabbitmq and
                            memcached secret. Should be grather than 0. Increase only by one is allowed.
                            Once added, removing this field is not allowed.
                certificates:
                  type: object
                  properties:
                    octavia:
                      type: object
                      properties:
                        amphora:
                          type: object
                          properties:
                            rotation_id:
                              type: integer
                              description: |
                                Integer incremental field for triggering rotation of amphora certificates
                                used by Octavia loadbalancers. Should be greater than 0. Increase only
                                by one is allowed. Once added, removing this field is not allowed.
                watched:
                  type: object
                  description: |
                    The object that contains information of objects that rockoon
                    is watching for. Changin fields of this object will trigger update of
                    all children.
                  properties:
                    configmaps:
                      type: object
                      x-kubernetes-preserve-unknown-fields: true
                      description: Contains hash value of configmap for which we are watching for.
                    value_from:
                      type: object
                      properties:
                        secret:
                          type: object
                          x-kubernetes-preserve-unknown-fields: true
                          description: Contains hash value of secrets for value substitution object.
                    ceph:
                      type: object
                      properties:
                        secret:
                          type: object
                          properties:
                            hash:
                              type: string
                              description: |
                                The hash value for secret, is a trigger to reload ceph
                                metadata
                    osdplsecret:
                      type: object
                      properties:
                        hash:
                          type: string
                          description: |
                            The hash value of osdplsecret object.
                    neutron:
                      properties:
                        bgpvpn_neighbor_secret:
                          properties:
                            hash:
                              description: |
                                The hash value for secret, is a trigger to reload neutron bgpvpn metadata
                              type: string
                          type: object
                      type: object
                    tf:
                      properties:
                        secret:
                          properties:
                            hash:
                              description: |
                                The hash value for secret, is a trigger to reload octavia
                              type: string
                          type: object
                      type: object
      subresources:
        # status enables the status subresource.
        status: {}
      additionalPrinterColumns:
      - name: OpenStack
        type: string
        description: OpenStack release
        jsonPath: .spec.openstack_version
      - name: Age
        type: date
        jsonPath: .metadata.creationTimestamp
      - name: Draft
        type: boolean
        jsonPath: .spec.draft
  # either Namespaced or Cluster
  scope: Namespaced
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: openstackdeployments
    # singular name to be used as an alias on the CLI and for display
    singular: openstackdeployment
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: OpenStackDeployment
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
      - osdpl
    categories:
      - all
