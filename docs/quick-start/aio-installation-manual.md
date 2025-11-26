# All in One Installation

This paragraph provides a guide how to deploy single node deployment with
[k0s](https://docs.k0sproject.io/stable/) based Kubernetes cluster and
openstack deployed by Rockoon controller.

### Example command to create an appropriate kvm VM on Linux with `virt-manager`

Needs `virt-manager`, `libvirt`, and `qemu-kvm` installed.

Change the path to the public SSH key as you need, the user in the image is
`ubuntu`.

```bash
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
qemu-img create -F qcow2 -f qcow2 -b noble-server-cloudimg-amd64.img rockoon.qcow2 100G
virt-install \
    --name rockoon \
    --import \
    --disk path=$PWD/rockoon.qcow2,format=qcow2 \
    --vcpus=8 \
    --memory=16384 \
    --network "network=default,model=virtio" \
    --osinfo "ubuntu24.04" \
    --arch x86_64 \
    --graphics vnc,listen=0.0.0.0 \
    --cloud-init clouduser-ssh-key=$HOME/.ssh/id_rsa.pub \
    --virt-type kvm \
    --watchdog=default \
    --noautoconsole
```
Once the VM is running, run `virsh domifaddr rockoon` to find the IP address
of the VM to SSH to.

### Example command to create an appropriate qemu VM on MacOS with `lima`

As mentioned, only Intel-based Macs are currently supported.

```bash
brew install lima
limactl create \
    --name=rockoon \
    --tty=false \
    --cpus 8 \
    --disk 100 \
    --memory 16 \
    --plain \
    --arch x86_64 \
    --vm-type qemu \
    --set '.cpuType.x86_64 = "host"' \
    template://ubuntu-24.04
limactl start rockoon
ssh -F ~/.lima/rockoon/ssh.config lima-rockoon
```

## Trigger Deployment

1. Download repository with rockoon
  ```bash
  git clone https://github.com/Mirantis/rockoon
  ```

2. Trigger deployment
  ```bash
  cd rockoon/virtual_lab/
  sudo bash install.sh
  ```
