# OpenStack Controller Admission

The [CustomResourceDefinition](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
resource in Kubernetes uses the [OpenAPI Specification version 2](https://swagger.io/specification/v2/) to specify the schema of
the resource defined. The Kubernetes API outright rejects the resources that do not pass this schema validation.

The language of the schema, however, is not expressive enough to define a specific validation logic that may be needed for a given
resource. For this purpose, Kubernetes enables the extension of its API with Dynamic Admission Control.

For the OpenStackDeployment (OsDpl) CR the ValidatingAdmissionWebhook is a natural choice. It is deployed as part of OpenStack Controller
in dedicated deployment by default and performs specific extended validations when an `OpenStackDeployment` CR is created or updated.

The inexhaustive list of additional validations includes:

 - Deny the OpenStack version downgrade
 - Deny the OpenStack version skip-level upgrade
 - Deny the OpenStack master version deployment
 - Deny upgrade to the OpenStack master version
 - Deny deploying invalid configuration
