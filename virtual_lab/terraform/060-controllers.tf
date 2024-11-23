#### Controllers ####

# Render a multi-part cloud-init config
data "cloudinit_config" "config" {
  for_each      = var.controller_instance_names
  gzip          = true
  base64_encode = true
  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content      = templatefile("templates/init.tpl", {ssh_private_key_base64=base64encode(file(var.ssh["private_key_file"]))})
  }
  part {
    content_type = "text/x-shellscript"
    content      = templatefile("templates/controller_init.tpl", {})
  }
}

# Create instance
resource "openstack_compute_instance_v2" "controller" {
  for_each          = var.controller_instance_names
  name              = "${var.identifier}-server-${each.value}"
  image_id          = var.image
  flavor_name       = var.controller_flavor
  key_pair          = openstack_compute_keypair_v2.user_key.name
  user_data         = data.cloudinit_config.config[each.value].rendered
  network {
    port = openstack_networking_port_v2.controller[each.value].id
  }
  provisioner "remote-exec" {
    connection {
      host        = openstack_networking_floatingip_v2.controller[each.value].address
      user        = var.ssh["user_name"]
    }
    inline = [
      "cloud-init status --wait"
    ]
  }
}
# Create network port
resource "openstack_networking_port_v2" "controller" {
  for_each              = var.controller_instance_names
  name                  = "${var.identifier}-port-${each.value}"
  network_id            = openstack_networking_network_v2.lcm.id
  admin_state_up        = true
  port_security_enabled = false
  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.lcm.id
  }
}
# Create floating ip
resource "openstack_networking_floatingip_v2" "controller" {
  for_each   = var.controller_instance_names
  pool       = var.public_network
  port_id    = openstack_networking_port_v2.controller[each.value].id
  depends_on = [openstack_networking_router_interface_v2.lcm]
}
