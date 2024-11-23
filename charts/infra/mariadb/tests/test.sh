function log {
    local msg="$1"
    echo "$(date) $msg"
}

function wait_healthy {
    log "  Waiting mariadb pods are ready"
    while [[ $(kubectl -n openstack get pods |grep mariadb-server |grep "2/2     Running" | wc -l) -ne 3 ]]; do
	    sleep 5
    done
    log "  All pods are ready"
    kubectl -n openstack get pods |grep mariadb-server
}

function kill {
  local to_kill="$1"
  local to_delete="$2"
  for pod in $to_kill; do
      log "  Killing -9 $pod"
      kubectl -n openstack exec -it mariadb-server-$pod -- bash -c "kill -9 \$(pidof mysqld)"
  done
  for pod in $to_delete; do
    kubectl -n openstack delete pod mariadb-server-$pod &
  done
  sleep 1
}

log "Killing one -9:"
kill 0 "1 2"
wait_healthy

kill 1 "0 2"
wait_healthy

kill 2 "0 1"
wait_healthy
log "\n\n\n"

log "Killing all graceful:"
kill "" "0 1 2"
wait_healthy
log "\n\n\n"

for i in {0..2}; do
  log "Kill one $i graceful:"
  kill "" "$i"
  wait_healthy
done
log "\n\n\n"


for i in {0..2}; do
  log "Wipe one $i and restart:"
  kubectl -n openstack exec -it mariadb-server-$i -- bash -c "rm -rf /var/lib/mysql/*"
  kill "" "$i"
  wait_healthy
done
log "\n\n\n"

for i in {0..2}; do
  log "Wipe one $i and kill:"
  kubectl -n openstack exec -it mariadb-server-$i -- bash -c "rm -rf /var/lib/mysql/*"
  kill "$i" ""
  wait_healthy
done
log "\n\n\n"
