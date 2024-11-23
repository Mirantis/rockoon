#!/bin/bash
set -ex

SOURCE_FILE="/tmp/SERVICES_TO_CLEAN"

echo "Current cinder service list:"

cinder-manage service list

if [ -s "${SOURCE_FILE}" ]; then
    LINES=$(cat ${SOURCE_FILE})
    echo "Next services will be removed:"
    echo "${LINES}"
else
   echo "Nothing to remove"
   exit 0
fi

echo "${LINES}" | while read -r line; do
    echo $line;
    cinder-manage service remove $line
done

rm -f "${SOURCE_FILE}"
