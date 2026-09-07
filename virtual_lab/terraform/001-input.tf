# Define input variables
# Cluster
variable "identifier" {
  type    = string
  default = "oc-virtual-lab"
}
variable "image" {
  type        = string
  description = "Name of image to use for servers"
  default     = "e76363e2-c212-48d3-9373-678a70bd265e"
}
variable "controller_flavor" {
  type    = string
  default = "mosk.s.ucp"
}

variable "os_controller_flavor" {
  type    = string
  default = "mosk.l.control"
}

variable "os_compute_flavor" {
  type    = string
  default = "mosk.s.compute"
}

variable "public_network" {
  type    = string
  default = "public"
}
variable "dns_nameservers" {
  type    = list(string)
  default = []
}
variable "ssh" {
  type = map(string)
  default = {
    user_name        = "ubuntu"
    public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBOrW5VEu0ZadTxfTv0S6TnnMaeOgeSpdJA0pkXGegX0qVZqr4y6Ugfxji6XOv5mUqtAI6/jhuSSP3UkmfsIoqTOL5ZkBEirTL/az8z+xrSf262mZEAowQgBML+NipKQPhoejIYWSiNvTBZRZgV9a5wSbdbpDYuu4bC9KGmNf4A+TwObTFN70v64r2+3wzj27f4eok4Jec4I9r3evAgp03GpKQ6A8AyHIrwbres9OSmpZTxoar0Nv42gL/2Ncso6O6XXVjNqZN4xrgbBHXOGYVJierEuYQvMhGEiBSa2H5uB2B1JAm/DG7oQ2b74lYJI4mutdsZZo7D3a0rmWh6cDj"
    private_key_file = "/Users/vasylsaienko/.ssh/devcloud_rsa"
  }
}
# Controlers
variable "controller_instance_names" {
  type = set(string)
  default = [
    "ctl-01",
  ]
}

variable "os_controller_instance_names" {
  type = set(string)
  default = [
  ]
}

variable "os_compute_instance_names" {
  type = set(string)
  default = [
  ]
}

variable "lcm_network" {
  type        = map(string)
  description = "The details of LCM network"
  default = {
    subnet_name = "subnet-lcm"
    cidr        = "10.10.11.0/24"
  }
}
