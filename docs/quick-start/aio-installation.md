# All in One Installation

This paragraph provides a guide how to deploy single node deployment with
[k0s](https://docs.k0sproject.io/stable/) based Kubernetes cluster and
openstack deployed by Rockoon controller.

## Prepare VM

For the deployment we will need Virtual Machine with following minimal requirements.

Minimal VM requirements

| Resource | Amount |
| -------- | ------ |
| RAM  | 16Gb       |
| CPU  | 8          |
| DISK | 100Gb      |

Supported operation systems

* Ubuntu 22.04 (x86_64)


## Trigger Deployment

1. Download repository with rockoon
  ```bash
  git clone https://github.com/Mirantis/rockoon
  ```

2. Trigger deployment
  ```bash
  cd rockoon/virtual_lab/
  bash install.sh
  ```
