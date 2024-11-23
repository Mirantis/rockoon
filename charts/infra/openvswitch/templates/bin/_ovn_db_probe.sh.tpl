#!/bin/bash
set -ex

COMPONENT=$1
PROBE_TYPE=$2

DB_SOCK="unix:/run/ovn/ovn${COMPONENT}_db.sock "

function generic_probe {
    local component=$1
    binary="/usr/bin/ovn-${component}ctl"
    $binary --db=${DB_SOCK} --no-leader-only show
}

function sb_liveness {
    generic_probe sb
}

function nb_liveness {
    generic_probe nb
}

function sb_readiness {
    generic_probe sb
}

function nb_readiness {
    generic_probe nb
}

${COMPONENT}_${PROBE_TYPE}
