# Introduction
Rockoon can be deployed in different ways. For a quick start in a preconfigured environment,
we have created the TryMOSK image, which allows you to easily launch a virtual machine with
Rockoon and additional tools. The process of deploying Rockoon using the TryMOSK image is
described in the [TryMOSK (Using pre-built image)](trymosk-installation-aws.md) section.

Another option is to deploy Rockoon on your own existing virtual machine. In this case, the
sources will be downloaded from GitHub, and some of the Docker images will be built on the
virtual machine during the deployment process. This method is described in the
**Manual Install (Advanced)** section.

## Host
At the moment hosts with non-x86_64 CPU (like Apple Silicon) are not supported.
The required full CPU emulation for virtual machine introduces
too much overhead, making the system too slow and unusable.

## Prepare VM
For the deployment we will need Virtual Machine with following minimal requirements.

Minimal VM requirements

| Resource | Amount |
| -------- |------- |
| RAM      | 16Gb   |
| CPU      | 4      |
| DISK     | 40Gb   |

Supported operation systems for **Manual install (Advanced)**

* Ubuntu 22.04 (x86_64)
