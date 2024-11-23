from rockoon.filters.tempest import base_section


class LoadBalancer(base_section.BaseSection):
    name = "load_balancer"
    options = [
        "region",
        "catalog_type",
        "endpoint_type",
        "build_interval",
        "build_timeout",
        "octavia_svc_username",
        "check_interval",
        "check_timeout",
        "lb_build_interval",
        "lb_build_timeout",
        "member_role",
        "admin_role",
        "scp_connection_timeout",
        "scp_connection_attempts",
        "provider",
        "RBAC_test_type",
        "enabled_provider_drivers",
        "loadbalancer_topology",
        "expected_flavor_capability",
        "test_with_ipv6",
        "disable_boot_network",
        "enable_security_groups",
        "vip_subnet_cidr",
        "vip_ipv6_subnet_cidr",
        "member_1_ipv4_subnet_cidr",
        "member_1_ipv6_subnet_cidr",
        "member_2_ipv4_subnet_cidr",
        "member_2_ipv6_subnet_cidr",
        "amphora_ssh_user",
        "amphora_ssh_key",
        "random_server_name_length",
        "availability_zone",
    ]

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def catalog_type(self):
        pass

    @property
    def endpoint_type(self):
        pass

    @property
    def build_interval(self):
        pass

    @property
    def build_timeout(self):
        pass

    @property
    def octavia_svc_username(self):
        pass

    @property
    def check_interval(self):
        pass

    @property
    def check_timeout(self):
        pass

    @property
    def lb_build_interval(self):
        pass

    @property
    def lb_build_timeout(self):
        pass

    @property
    def member_role(self):
        pass

    @property
    def admin_role(self):
        pass

    @property
    def scp_connection_timeout(self):
        pass

    @property
    def scp_connection_attempts(self):
        pass

    @property
    def provider(self):
        version = self.spec["openstack_version"]
        # NOTE(vsaienko): in Queens default_provider_driver was not exist
        # do not handle this and return default value
        if version == "queens":
            return "octavia"
        return self.get_values_item(
            "octavia",
            "conf.octavia.api_settings.default_provider_driver",
            "amphora",
        )

    @property
    def RBAC_test_type(self):
        # do not test rbac policies by octavia tempest plugin,
        # current tests are not optimal.
        # should be tested by separate project - patrole.
        return "none"

    @property
    def enabled_provider_drivers(self):
        providers = self.get_values_item(
            "octavia",
            "conf.octavia.api_settings.enabled_provider_drivers",
            "amphora:amphora:The Octavia Amphora driver.",
        )
        return providers

    @property
    def loadbalancer_topology(self):
        pass

    @property
    def expected_flavor_capability(self):
        pass

    @property
    def disable_boot_network(self):
        pass

    @property
    def test_with_ipv6(self):
        if self.tf_enabled():
            return False

    @property
    def enable_security_groups(self):
        # If 'security-group' in api_extension, return True
        return True

    @property
    def vip_subnet_cidr(self):
        pass

    @property
    def vip_ipv6_subnet_cidr(self):
        pass

    @property
    def member_1_ipv4_subnet_cidr(self):
        pass

    @property
    def member_1_ipv6_subnet_cidr(self):
        pass

    @property
    def member_2_ipv4_subnet_cidr(self):
        pass

    @property
    def member_2_ipv6_subnet_cidr(self):
        pass

    @property
    def amphora_ssh_user(self):
        pass

    @property
    def amphora_ssh_key(self):
        pass

    @property
    def random_server_name_length(self):
        pass

    @property
    def availability_zone(self):
        pass
