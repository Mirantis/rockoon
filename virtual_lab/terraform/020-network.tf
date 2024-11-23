#### NETWORK CONFIGURATION ####
# Router creation
data "openstack_networking_network_v2" "public" {
  name = var.public_network
}
resource "openstack_networking_router_v2" "generic" {
  name                = "${var.identifier}-router"
  external_network_id = data.openstack_networking_network_v2.public.id
}
#### APP NETWORK ####
resource "openstack_networking_network_v2" "lcm" {
  name = "${var.identifier}-network-lcm"
}
# Subnet lcm network
resource "openstack_networking_subnet_v2" "lcm" {
  name            = join("-", [var.identifier, var.lcm_network["subnet_name"]])
  network_id      = openstack_networking_network_v2.lcm.id
  cidr            = var.lcm_network["cidr"]
  dns_nameservers = var.dns_nameservers
}
# Router interface configuration
resource "openstack_networking_router_interface_v2" "lcm" {
  router_id = openstack_networking_router_v2.generic.id
  subnet_id = openstack_networking_subnet_v2.lcm.id
}
