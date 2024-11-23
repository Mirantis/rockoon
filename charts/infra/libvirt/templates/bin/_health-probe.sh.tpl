#!/usr/bin/env bash


COMPONENT="$1"
PROBE_TYPE="$2"

function virtlogd_probe {
    /usr/bin/virt-admin -c virtlogd:///system server-list
}

function virtlogd_liveness {
    virtlogd_probe
}

function virtlogd_readiness {
    virtlogd_probe
}


function libvirt_liveness {
    if [[ -c /dev/kvm ]]; then
        actual_stat=$(stat -c "%U %G %a" /dev/kvm)
        expected_stat="root kvm 660"
        if [[ "$actual_stat" != "$expected_stat" ]]; then
            echo "/dev/kvm has wrong permissions ${actual_stat}, expected ${expected_stat}"
            exit 1
        fi
    fi
    /usr/bin/virsh connect
}

function libvirt_readiness {
    /usr/bin/virsh connect
}

${COMPONENT}_${PROBE_TYPE}
