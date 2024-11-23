#!/bin/bash
set -ex

rm -f /var/run/virtlogd.pid

/usr/sbin/virtlogd
