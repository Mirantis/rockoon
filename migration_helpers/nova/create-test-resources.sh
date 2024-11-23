export NETWORK_NAME=${NETWORK_NAME:-heat-net}
export PUBLIC_NETWORK_NAME=${PUBLIC_NETWORK_NAME:-public}
export IMAGE_NAME=${IMAGE_NAME:-TestCirros-0.4.0}
export FLAVOR_NAME=${FLAVOR_NAME:-m1.tiny_test}
export SERVER_NAME_PREFIX=${SERVER_NAME_PREFIX:-Test}
export SERVER_COUNT=${SERVER_COUNT:-5}


for number in $(seq 1 $SERVER_COUNT); do
  server_name=${SERVER_NAME_PREFIX}-$number
  port_name=port-${server_name}
  port_id=$(openstack port create ${port_name} --disable-port-security --no-security-group --network $NETWORK_NAME -f value -c id)
  server_name=${SERVER_NAME_PREFIX}-$number
  openstack server create --port ${port_id} --image $IMAGE_NAME --flavor ${FLAVOR_NAME} ${server_name}
  floating_id=$(openstack floating ip create ${PUBLIC_NETWORK_NAME} -f value -c id)

  openstack server add floating ip ${server_name} $floating_id
done
