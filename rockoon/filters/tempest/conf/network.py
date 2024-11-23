from rockoon.filters.tempest import base_section


class Network(base_section.BaseSection):
    name = "network"
    options = [
        "build_interval",
        "build_timeout",
        "catalog_type",
        "default_network",
        "dns_servers",
        "endpoint_type",
        "floating_network_name",
        "port_vnic_type",
        "project_network_cidr",
        "project_network_mask_bits",
        "project_network_v6_cidr",
        "project_network_v6_mask_bits",
        "project_networks_reachable",
        "public_network_id",
        "public_router_id",
        "region",
        "shared_physical_network",
        "service_ports_number",
    ]

    @property
    def build_interval(self):
        pass

    @property
    def build_timeout(self):
        pass

    @property
    def catalog_type(self):
        pass

    @property
    def default_network(self):
        pass

    @property
    def dns_servers(self):
        pass

    @property
    def endpoint_type(self):
        pass

    @property
    def floating_network_name(self):
        pass

    @property
    def port_vnic_type(self):
        pass

    @property
    def project_network_cidr(self):
        pass

    @property
    def project_network_mask_bits(self):
        pass

    @property
    def project_network_v6_cidr(self):
        pass

    @property
    def project_network_v6_mask_bits(self):
        pass

    @property
    def project_networks_reachable(self):
        pass

    @property
    def public_network_id(self):
        pass

    @property
    def public_router_id(self):
        pass

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def shared_physical_network(self):
        pass

    @property
    def service_ports_number(self):
        if self.get_values_item(
            "neutron", "manifests.daemonset_portprober_agent", False
        ):
            # Neutron Portprober agent creates 2 ports in network,
            # they have assigned ips even when dhcp is disabled.
            return 2
