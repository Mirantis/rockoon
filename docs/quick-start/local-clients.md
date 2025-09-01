# Using kubectl and helm with Rockoon AIO

To configure and manage Rockoon AIO, you need the **kubectl** and **helm** command-line tools.
These tools are already installed on your Rockoon AIO instance, but you can also install them
locally on your computer.

1. Install kubectl and helm locally. Follow the official installation instructions:
    * **kubectl:** [https://kubernetes.io/docs/tasks/tools/\#kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
    * **helm:** [https://helm.sh/docs/intro/install/](https://helm.sh/docs/intro/install/)

2. Retrieve the configuration file from the Rockoon AIO instance.  
The kubeconfig file for Rockoon AIO is located on the instance at */root/.kube/config*.
You can retrieve it over SSH. For **Linux/macOS**, run:
```shell
ssh -l ubuntu 18.218.29.107 sudo cat /root/.kube/config > ~/aio_kube_config.yaml
```
In this example:
    * `18.218.29.107` is the public IPv4 address of your Rockoon AIO instance.
    * The file is saved locally as `aio_kube_config.yaml` in your home directory.

3. Use kubectl and helm with the configuration file  
When connected to the Rockoon AIO instance via sshuttle or OpenVPN, you can run commands like:
```shell
kubectl --kubeconfig ~/aio_kube_config.yaml ...
helm --kubeconfig ~/aio_kube_config.yaml ...
```
> **Note:** If you want to avoid specifying `--kubeconfig` each time, move the configuration file to *~/.kube/config*.  
> **Warning**: This will overwrite existing Kubernetes configuration file at that location.

4. Handling self-signed SSL certificates for TryMOSK installation  
TryMOSK uses a self-signed SSL certificate for its proxy-server. If running `helm` commands
from your local computer, you must add `--insecure-skip-tls-verify` flag to skip TLS verification.
