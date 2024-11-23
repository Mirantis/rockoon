from rockoon import layers
from rockoon.filters.tempest import base_section


class NeutronDynamicRoutingOptions(base_section.BaseSection):
    name = "dynamic_routing"
    options = [
        "frr_docker_image",
        "frr_provider_ipv4_ips",
        "frr_provider_ipv6_ips",
        "frr_bgp_ipv6_enabled",
        "frr_bgp_timeout",
        "frr_bgp_ipv4_control_cidr",
        "frr_bgp_ipv6_control_cidr",
    ]

    @property
    def frr_docker_image(self):
        artifacts = layers.render_artifacts(self.spec)
        return artifacts["frr"]

    @property
    def frr_provider_ipv4_ips(self):
        pass

    @property
    def frr_provider_ipv6_ips(self):
        pass

    @property
    def frr_bgp_ipv6_enabled(self):
        pass

    @property
    def frr_bgp_timeout(self):
        pass

    @property
    def frr_bgp_ipv4_control_cidr(self):
        pass

    @property
    def frr_bgp_ipv6_control_cidr(self):
        pass
