# OpenStack Controller

`OpenStack controller` is running as a deployment in Kubernetes with multiple
subcontrollers that are running as dedicated containers in the deployment.
Each subcontroller 


| <div style="width:150px">Container</div> | Description                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `osdpl`                  | The core subcontroller that handles changes of `OpenStackDeployment` object          |
| `secrets`                | Subcontroller that provides data excange between different components                |
| `health`                 | Subcontroller that constantly watching for OpenStack health and reporting its status |
| `node`                   | Subcontroller that watches for `Node` object                                         |
| `nodemaintenancerequest` | Subcontroller that provides integration with Kubernetes lifecycle management         |
| `ceph-secrets`           | Subcontroller that provides integration with `Ceph` storage                          |
| `osdplstatus`            | Subcontroller responsible for status reporting                                       |
| `tf-secrets`             | Subcontroller that provides integration with TungstenFabric                          |
