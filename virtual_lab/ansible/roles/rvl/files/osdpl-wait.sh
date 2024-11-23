#!/bin/bash

OSDPL_NAME=${OSDPL_NAME:-osh-dev}
NAMESPACE=${NAMESPACE:-openstack}

function wait_for_pods {
    local namespace=$1
    local component_filter=${2:-""}
    local timeout=${3:-900}
    local delay=${4:-30}
    end=$(date +%s)
    end=$((end + timeout))
    echo "Waiting for pods ${component_filter} are ready in namespace: ${namespace}"
    while true; do
        if kubectl get pods --namespace=${namespace} $component_filter 2>&1 |grep -q 'No resources found'; then
            continue
        fi
        kubectl get pods --namespace=${namespace} $component_filter -o json | jq -r \
            '.items[].status.phase' | grep Pending > /dev/null && \
            PENDING="True" || PENDING="False"
        query='.items[]|select(.status.phase=="Running")'
        query="$query|.status.containerStatuses[].ready"
        kubectl get pods --namespace=${namespace} $component_filter -o json | jq -r "$query" | \
            grep false > /dev/null && READY="False" || READY="True"
        kubectl get jobs --namespace=${namespace} $component_filter -o json | jq -r \
            '.items[] | .spec.completions == .status.succeeded' | \
            grep false > /dev/null && JOBR="False" || JOBR="True"
        [ $PENDING == "False" -a $READY == "True" -a $JOBR == "True" ] && \
            break || true
        sleep 5
        now=$(date +%s)
        if [ $now -gt $end ] ; then
            echo "Containers failed to start after $timeout seconds"
            echo
            kubectl get pods --namespace ${namespace} $component_filter -o wide
            echo
            if [ $PENDING == "True" ] ; then
                echo "Some pods are in pending state:"
                kubectl get pods $component_filter --field-selector=status.phase=Pending -n ${namespace} -o wide
            fi
            [ $READY == "False" ] && echo "Some pods are not ready"
            [ $JOBR == "False" ] && echo "Some jobs have not succeeded"
            exit -1
        fi
	sleep $delay
    done
}

function wait_osdpl_applied {
    local osdpl_name="$1"
    local namespace="$2"
    local timeout="${3:-900}"
    local delay="${4:-15}"
    local osdpl_state=""

    end=$(date +%s)
    end=$((end + timeout))
    echo "Waiting OpenStackDeployment ${osdpl_name} is APPLIED"
    while true; do
        osdpl_state=$(kubectl -n ${namespace} get osdplst ${osdpl_name} -o jsonpath='{.status.osdpl.state}')
        now=$(date +%s)
        if [ "${osdpl_state}" == "APPLIED" ]; then
            break
        fi
        if [ $now -gt $end ] ; then
            echo "OpenStackDeployment ${osdpl_name} is not in APPLIED state. Current state is ${osdpl_state}"
	    exit 1
        fi
	sleep $delay
    done
}

wait_osdpl_applied $OSDPL_NAME $NAMESPACE
wait_for_pods $NAMESPACE "" 3600 30
