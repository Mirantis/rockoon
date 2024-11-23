#!/bin/bash

{{/*
Copyright 2017 The Openstack-Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

# Save trace setting
_XTRACE_FUNCTIONS=$(set +o | grep xtrace)
set +o xtrace

#
# functions-common - Common functions used by DevStack components
#
# Link for reference
# https://github.com/openstack/devstack/blob/master/functions-common

# Common Functions
# ================

# Checks an environment variable is not set or has length 0 OR if the
# exit code is non-zero and prints "message" and exits
# NOTE: env-var is the variable name without a '$'
# die_if_not_set $LINENO env-var "message"
function die_if_not_set {
    local exitcode=$?
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace
    local line=$1; shift
    local evar=$1; shift
    if ! is_set $evar || [ $exitcode != 0 ]; then
        die $line "$*"
    fi
    $xtrace
}

# Test if the named environment variable is set and not zero length
# is_set env-var
function is_set {
    local var=\$"$1"
    eval "[ -n \"$var\" ]" # For ex.: sh -c "[ -n \"$var\" ]" would be better, but several exercises depends on this
}

#
# **inc/ini-config** - Configuration/INI functions
#
# Support for manipulating INI-style configuration files
#
# These functions have no external dependencies and no side-effects
# Link for reference
# https://github.com/openstack/devstack/blob/master/inc/ini-config

# Config Functions
# ================

# Determinate is the given option present in the INI file
# ini_has_option [-sudo] config-file section option
function ini_has_option {
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace
    local sudo=""
    if [ $1 == "-sudo" ]; then
        sudo="sudo "
        shift
    fi
    local file=$1
    local section=$2
    local option=$3
    local line

    line=$($sudo sed -ne "/^\[$section\]/,/^\[.*\]/ { /^$option[ \t]*=/ p; }" "$file")
    $xtrace
    [ -n "$line" ]
}

# Set an option in an INI file
# iniset [-sudo] config-file section option value
#  - if the file does not exist, it is created
function iniset {
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace
    local sudo=""
    local sudo_option=""
    if [ $1 == "-sudo" ]; then
        sudo="sudo "
        sudo_option="-sudo "
        shift
    fi
    local file=$1
    local section=$2
    local option=$3
    local value=$4

    if [[ -z $section || -z $option ]]; then
        $xtrace
        return
    fi

    if ! $sudo grep -q "^\[$section\]" "$file" 2>/dev/null; then
        # Add section at the end
        echo -e "\n[$section]" | $sudo tee --append "$file" > /dev/null
    fi
    if ! ini_has_option $sudo_option "$file" "$section" "$option"; then
        # Add it
        $sudo sed -i -e "/^\[$section\]/ a\\
$option = $value
" "$file"
    else
        local sep
        sep=$(echo -ne "\x01")
        # Replace it
        $sudo sed -i -e '/^\['${section}'\]/,/^\[.*\]/ s'${sep}'^\('"${option}"'[ \t]*=[ \t]*\).*$'${sep}'\1'"${value}"${sep} "$file"
    fi
    $xtrace
}

# Restore xtrace
$_XTRACE_FUNCTIONS

# Local variables:
# mode: shell-script
# End: