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
    public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp0evjOaK8c8SKYK4r2+0BN7g+8YSvQ2n8nFgOURCyvkJqOHi1qPGZmuN0CclYVdVuZiXbWw3VxRbSW3EH736VzgY1U0JmoTiSamzLHaWsXvEIW8VCi7boli539QJP0ikJiBaNAgZILyCrVPN+A6mfqtacs1KXdZ0zlMq1BPtFciR1JTCRcVs5vP2Wwz5QtY2jMIh3aiwkePjMTQPcfmh1TkOlxYu5IbQyZ3G1ahA0mNKI9a0dtF282av/F6pwB/N1R1nEZ/9VtcN2I1mf1NW/tTHEEcTzXYo1R/8K9vlqAN8QvvGLZtZduGviNVNoNWvoxaXxDt8CPv2B2NCdQFZp"
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
