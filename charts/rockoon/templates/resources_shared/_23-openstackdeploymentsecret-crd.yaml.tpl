apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: openstackdeploymentsecrets.lcm.mirantis.com
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
              properties:
                nodes:
                  type: object
                  # NOTE(vsaienko): the schema is validated by admission controller
                  description: Object that describes node specific overrides.
                  x-kubernetes-preserve-unknown-fields: true
                features:
                  type: object
                  required:
                    - ssl
                  properties:
                    ssl:
                      type: object
                      required:
                       - public_endpoints
                      properties:
                        public_endpoints:
                          type: object
                          required:
                            - ca_cert
                            - api_cert
                            - api_key
                          properties:
                            ca_cert:
                              description: |
                                CA certificate
                              type: string
                            api_cert:
                              description: |
                                API server certificate
                              type: string
                            api_key:
                              description: |
                                API server private key
                              type: string
                    barbican:
                      type: object
                      properties:
                        backends:
                          type: object
                          properties:
                            vault:
                              type: object
                              properties:
                                approle_role_id:
                                  description: |
                                    Specifies the app role ID
                                  type: string
                                approle_secret_id:
                                  description: |
                                     Specifies the secret ID created for the app role
                                  type: string
                    database:
                      type: object
                      properties:
                        backup:
                          type: object
                          properties:
                            sync_remote:
                              type: object
                              properties:
                                remotes:
                                  type: object
                                  x-kubernetes-preserve-unknown-fields: true
                    keystone:
                      type: object
                      properties:
                        domain_specific_configuration:
                          type: object
                          properties:
                            enabled:
                              type: boolean
                              description: Enable domain specific keystone configuration
                            ks_domains:
                              type: object
                              description: |
                                The list of domain specific configuration options.
                              x-kubernetes-preserve-unknown-fields: true
                    neutron:
                      type: object
                      required:
                        - baremetal
                      properties:
                        baremetal:
                          type: object
                          properties:
                            ngs:
                              type: object
                              properties:
                                hardware:
                                  type: object
                                  x-kubernetes-preserve-unknown-fields: true
                services:
                  x-kubernetes-preserve-unknown-fields: true
                  type: object
                  description: this is arbitrary JSON
            status:
              x-kubernetes-preserve-unknown-fields: true
              type: object
              description: this is arbitrary JSON
      additionalPrinterColumns:
      - name: Hash
        type: string
        description: OpenStackDeploymentSecret hash
        jsonPath: .status.hash
      - name: Age
        type: date
        jsonPath: .metadata.creationTimestamp
  # either Namespaced or Cluster
  scope: Namespaced
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: openstackdeploymentsecrets
    # singular name to be used as an alias on the CLI and for display
    singular: openstackdeploymentsecret
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: OpenStackDeploymentSecret
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
      - osdplsecret
    categories:
      - all
