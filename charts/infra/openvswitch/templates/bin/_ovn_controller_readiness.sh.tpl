#!/bin/bash
set -ex

/usr/bin/ovs-vsctl list Open_Vswitch

if ! pidof ovn-controller > /dev/null 2>&1 ; then
    echo "The OVN controller pid not found"
    exit 1
fi