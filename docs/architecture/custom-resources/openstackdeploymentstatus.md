# OpenStackDeploymentStatus Custom Resource

The resource of kind `OpenStackDeploymentStatus` is a custom resource that describes the status of an OpenStack deployment.
To obtain detailed information about the schema of an OpenStackDeploymentStatus custom resource:

```bash
kubectl get crd openstackdeploymentstatus.lcm.mirantis.com -o yaml
```

To obtain the status definition for a particular OpenStack deployment:
```bash
kubectl -n openstack get osdplst
```

Example of system response:

```bash
NAME      OPENSTACK VERSION   CONTROLLER VERSION   STATE     LCM PROGRESS   HEALTH   MOSK RELEASE
osh-dev   antelope            0.16.1.dev104        APPLIED   20/20          21/22    MOSK 24.1.3
```

Where:

- `OPENSTACK VERSION` displays the actual OpenStack version of the deployment
- `CONTROLLER VERSION` indicates the version of the Rockoon controller responsible for the deployment
- `STATE` reflects the current status of life-cycle management. The list of possible values includes:
- `APPLYING` indicates that some Kubernetes objects for applications are in the process of being applied
- `APPLIED` indicates that all Kubernetes objects for applications have been applied to the latest state
- `LCM PROGRESS` reflects the current progress of STATE in the format X/Y, where X denotes the number of applications with Kubernetes objects applied and in the actual state, and Y represents the total number of applications managed by the Rockoon controller
- `HEALTH` provides an overview of the current health status of the OpenStack deployment in the format X/Y, where X represents the number of applications with notReady pods, and Y is the total number of applications managed by the Rockoon controller
- `MOSK RELEASE` displays the current product release of the OpenStack deployment


Example of `OpenStackDeploymentStatus`

```yaml
kind: OpenStackDeploymentStatus
metadata:
  name: osh-dev
  namespace: openstack
spec: {}
status:
  handle:
    lastStatus: update
  health:
    barbican:
      api:
        generation: 2
        status: Ready
    cinder:
      api:
        generation: 2
        status: Ready
      backup:
        generation: 1
        status: Ready
      scheduler:
        generation: 1
        status: Ready
      volume:
        generation: 1
        status: Ready
  osdpl:
    cause: update
    changes: '((''add'', (''status'',), None, {''watched'': {''ceph'': {''secret'':
      {''hash'': ''0fc01c5e2593bc6569562b451b28e300517ec670809f72016ff29b8cbaf3e729''}}}}),)'
    controller_version: 0.5.3.dev12
    fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
    openstack_version: ussuri
    state: APPLIED
    timestamp: "2021-09-08 17:01:45.633143"
  services:
    baremetal:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:54.081353"
    block-storage:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:57.306669"
    compute:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:18.853068"
    coordination:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:00.593719"
    dashboard:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:57.652145"
    database:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:00.233777"
    dns:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:56.540886"
    identity:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:00.961175"
    image:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:58.976976"
    ingress:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:01.440757"
    key-manager:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:51.822997"
    load-balancer:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:02.462824"
    memcached:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:03.165045"
    messaging:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:58.637506"
    networking:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:35.553483"
    object-storage:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:01.828834"
    orchestration:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:01:02.846671"
    placement:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:58.039210"
    redis:
      controller_version: 0.5.3.dev12
      fingerprint: a112a4a7d00c0b5b79e69a2c78c3b50b0caca76a15fe7d79a6ad1305b19ee5ec
      openstack_version: ussuri
      state: APPLIED
      timestamp: "2021-09-08 17:00:36.562673"
```


## Health structure

The `health` subsection provides a brief output on services health of each component

## OsDpl structure

The `osdpl` subsection describes the overall status of the OpenStack deployment.


| <div style="width:150px">Element</div>                  | Description                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `cause`                  | The cause that triggered the LCM action: `update` when OsDpl is updated, `resume` when the OpenStack Controller is restarted  |
| `changes`                | A string representation of changes in the `OpenstackDeployment` object |
| `controller_version`     | The version of `rockoon` that handles the LCM action |
| `fingerprint`            | The SHA sum of the `OpenStackDeployment` object spec section |
| `openstack_version`      | The current OpenStack version specified in the `osdpl` object
| `state`                  | The current state of the LCM action.<br> - `APPLYING`: not all operations are completed <br> - `APPLIED`: all operations are completed |
| `timestamp`              | The timestamp of the status:osdpl section update |

## Services structure

The services subsection provides detailed information of LCM performed with a specific service. This is a dictionary where keys are service names, for example,
`baremetal` or `compute` and values are dictionaries with the following items.

Services structure elements

| <div style="width:150px">Element</div>                  | Description                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `controller_version` | The version of the `rockoon` that handles the LCM action on a specific service |
| `fingerprint` | The SHA sum of the `OpenStackDeployment` object spec section used when performing the LCM on a specific service |
| `openstack_version` | The OpenStack version specified in the `osdpl` object used when performing the LCM action on a specific service|
| `state` | The current state of the LCM action.<br> - `WAITING`: waiting for dependencies <br> - `APPLYING`: not all operations are completed <br> - `APPLIED`: all operations are completed |
| `timestamp` | The timestamp of the status:osdpl section update |
