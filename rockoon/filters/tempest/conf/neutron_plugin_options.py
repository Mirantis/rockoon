from rockoon.filters.tempest import base_section


class NeutronPluginOptions(base_section.BaseSection):
    name = "neutron_plugin_options"
    options = [
        "advanced_image_ref",
        "advanced_image_flavor_ref",
        "advanced_image_ssh_user",
        "available_type_drivers",
        "agent_availability_zone",
        "default_image_is_advanced",
        "dns_domain",
        "l3_agent_mode",
        "max_mtu",
        "max_networks_per_project",
        "multicast_group_range",
        "provider_net_base_segm_id",
        "provider_vlans",
        "q_agent",
        "specify_floating_ip_address_available",
        "ssh_proxy_jump_host",
        "ssh_proxy_jump_keyfile",
        "ssh_proxy_jump_password",
        "ssh_proxy_jump_port",
        "ssh_proxy_jump_username",
        "test_mtu_networks",
        "firewall_driver",
        "create_shared_resources",
        "snat_rules_apply_to_nested_networks",
    ]

    @property
    def advanced_image_ref(self):
        pass

    @property
    def advanced_image_flavor_ref(self):
        pass

    @property
    def advanced_image_ssh_user(self):
        pass

    @property
    def available_type_drivers(self):
        default_type_drivers = "flat,vlan,vxlan"
        if self.tf_enabled():
            return
        return (
            self.get_values_item(
                "neutron",
                "conf.plugins.ml2_conf.ml2.type_drivers",
            )
            or default_type_drivers
        )

    @property
    def agent_availability_zone(self):
        pass

    @property
    def default_image_is_advanced(self):
        pass

    @property
    def dns_domain(self):
        dns_domain = self.get_values_item(
            "neutron", "conf.neutron.DEFAULT.dns_domain"
        )
        if dns_domain:
            if dns_domain.endswith("."):
                return dns_domain[:-1]
            else:
                return dns_domain

    @property
    def l3_agent_mode(self):
        pass

    @property
    def max_mtu(self):
        pass

    @property
    def max_networks_per_project(self):
        pass

    @property
    def multicast_group_range(self):
        pass

    @property
    def provider_net_base_segm_id(self):
        pass

    @property
    def provider_vlans(self):
        pass

    @property
    def q_agent(self):
        pass

    @property
    def specify_floating_ip_address_available(self):
        pass

    @property
    def ssh_proxy_jump_host(self):
        pass

    @property
    def ssh_proxy_jump_keyfile(self):
        pass

    @property
    def ssh_proxy_jump_password(self):
        pass

    @property
    def ssh_proxy_jump_port(self):
        pass

    @property
    def ssh_proxy_jump_username(self):
        pass

    @property
    def test_mtu_networks(self):
        pass

    @property
    def firewall_driver(self):
        if self.get_spec_item("features.neutron.backend", "ml2") == "ml2/ovn":
            return "ovn"
        return self.get_values_item(
            "neutron",
            "conf.plugins.openvswitch_agent.securitygroup.firewall_driver",
        )

    @property
    def create_shared_resources(self):
        if self.tf_enabled():
            return False
        return True

    @property
    def snat_rules_apply_to_nested_networks(self):
        neutron_backend = self.get_spec_item("features.neutron.backend", "ml2")
        if neutron_backend == "ml2/ovn":
            return self.get_values_item(
                "neutron",
                "conf.neutron.ovn.ovn_router_indirect_snat",
            )

        return True


class DesignateFeatureEnabled(base_section.BaseSection):
    name = "designate_feature_enabled"
    options = [
        "segmentation_id",
    ]

    @property
    def segmentation_id(self):
        # NOTE(mkarpin): dns integration scenario may require to create
        # vxlan network with segment id out of configured vni ranges.
        # So setting segment id to highest possible value for vxlan.
        if self.get_spec_item("features.neutron.backend", "ml2") == "ml2/ovn":
            return "16711680"
        return "16777215"
