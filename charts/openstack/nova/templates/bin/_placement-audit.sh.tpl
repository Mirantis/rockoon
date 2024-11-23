#!/bin/bash
set -x
set -o pipefail

# Mask permissions to files 416 dirs 0750
umask 0027
rm -rf /tmp/audit_completed /tmp/audit.log
nova-manage placement audit --verbose 2>&1 | tee /tmp/audit.log
res=$?
if [[ $res -eq 3 ]]; then
    echo "Orphaned allocations detected"
    exit_code=0
else
    exit_code=$res
fi
echo -n $exit_code > /tmp/audit_completed
exit $exit_code