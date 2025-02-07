# Welcome to Rockoon Controller documentation

## Introduction

The Rockoon Controller is a [Kubernetes operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
that implements lifecycle management for OpenStack deployment.

The Rockoon is written in Python using [Kopf](https://github.com/nolar/kopf) as a Python framework to build
Kubernetes operators, and [Pykube](https://pykube.readthedocs.io/en/latest/).

The controller subscribes to changes to OpenStackDeployment [Kubernetes custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
and then reacts to these changes by creating, updating, or deleting appropriate resources in Kubernetes.

## Getting Help

* File a bug: [https://github.com/Mirantis/rockoon/issues](https://github.com/Mirantis/rockoon/issues)
* Join slack [channel](https://join.slack.com/t/rockoon/shared_invite/zt-2z5qxwyq9-061Kc3_j9s~l9CquGQNOSw/)

## Developer

* Contributing: [https://TODO]()
* Reference Architecture:  [https://mirantis.github.io/rockoon](https://mirantis.github.io/rockoon)
