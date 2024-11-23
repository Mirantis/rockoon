#!/bin/bash

# Returns version for os controller image
# <tag>: if current commit is tagged
# <latest-tag+1>-<devVersion> - if current commit in other branches

REPO_DIR=$(cd $(dirname "$0")/../ && pwd)
# Fetch version with setup.py to align with PBR's version calculation.
# Using rev-list may lead to confusion as it doesn't match PBR logic.
pushd $REPO_DIR > /dev/null
IMG_TAG=$(python3 setup.py --version 2>/dev/null | grep -v "Generating ChangeLog" | sed 's/.dev/-dev/g')
popd > /dev/null
echo $IMG_TAG
