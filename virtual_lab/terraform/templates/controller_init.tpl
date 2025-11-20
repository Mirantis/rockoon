#!/bin/bash


apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y python3-pip

PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install ansible git-review

ansible-galaxy collection install bodsch.core
ansible-galaxy collection install bodsch.scm
ansible-galaxy role install bodsch.k0s
