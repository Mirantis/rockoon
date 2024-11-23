from rockoon.filters.tempest import base_section

DEFAULT_HEAT_PLUGIN_PARAMETERS = {"auth_version": 3}


class HeatPlugin(base_section.BaseSection):
    name = "heat_plugin"
    options = [
        "admin_password",
        "admin_project_name",
        "admin_username",
        "auth_url",
        "auth_version",
        "boot_config_env",
        "build_interval",
        "build_timeout",
        "ca_file",
        "catalog_type",
        "connectivity_timeout",
        "convergence_engine_enabled",
        "disable_ssl_certificate_validation",
        "fixed_network_name",
        "fixed_subnet_name",
        "floating_network_name",
        "heat_config_notify_script",
        "image_ref",
        "instance_type",
        "ip_version_for_ssh",
        "keypair_name",
        "minimal_image_ref",
        "minimal_instance_type",
        "network_for_ssh",
        "password",
        "project_domain_id",
        "project_domain_name",
        "project_name",
        "region",
        "sighup_config_edit_retries",
        "sighup_timeout",
        "skip_functional_test_list",
        "skip_functional_tests",
        "skip_scenario_test_list",
        "skip_scenario_tests",
        "skip_test_stack_action_list",
        "ssh_channel_timeout",
        "ssh_timeout",
        "tenant_network_mask_bits",
        "user_domain_id",
        "user_domain_name",
        "username",
        "volume_size",
        "vm_to_heat_api_insecure",
    ]

    @property
    def admin_password(self):
        return self.get_keystone_credential("password")

    @property
    def admin_project_name(self):
        pass

    @property
    def admin_username(self):
        return self.get_keystone_credential("username")

    @property
    def auth_url(self):
        pass

    @property
    def auth_version(self):
        return DEFAULT_HEAT_PLUGIN_PARAMETERS["auth_version"]

    @property
    def boot_config_env(self):
        pass

    @property
    def build_interval(self):
        pass

    @property
    def build_timeout(self):
        pass

    @property
    def ca_file(self):
        pass

    @property
    def catalog_type(self):
        pass

    @property
    def connectivity_timeout(self):
        pass

    @property
    def convergence_engine_enabled(self):
        pass

    @property
    def disable_ssl_certificate_validation(self):
        ca_file_exists = self.get_values_item("heat", "conf.heat.ssl.ca_file")
        if ca_file_exists:
            return False
        return True

    @property
    def fixed_network_name(self):
        pass

    @property
    def fixed_subnet_name(self):
        pass

    @property
    def floating_network_name(self):
        pass

    @property
    def heat_config_notify_script(self):
        pass

    @property
    def image_ref(self):
        pass

    @property
    def instance_type(self):
        pass

    @property
    def ip_version_for_ssh(self):
        pass

    @property
    def keypair_name(self):
        pass

    @property
    def minimal_image_ref(self):
        pass

    @property
    def minimal_instance_type(self):
        pass

    @property
    def network_for_ssh(self):
        pass

    @property
    def password(self):
        return self.get_keystone_credential("password")

    @property
    def project_domain_id(self):
        return self.get_keystone_credential("project_domain_name")

    @property
    def project_domain_name(self):
        pass

    @property
    def project_name(self):
        return self.get_keystone_credential("project_name")

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def sighup_config_edit_retries(self):
        pass

    @property
    def sighup_timeout(self):
        pass

    @property
    def skip_functional_test_list(self):
        pass

    @property
    def skip_functional_tests(self):
        pass

    @property
    def skip_scenario_test_list(self):
        skip_list = []
        aodh_enabled = self.is_service_enabled("aodh")

        if not aodh_enabled:
            skip_list.append("AodhAlarmTest")

        return " ,".join(skip_list)

    @property
    def skip_scenario_tests(self):
        pass

    @property
    def skip_test_stack_action_list(self):
        pass

    @property
    def ssh_channel_timeout(self):
        pass

    @property
    def ssh_timeout(self):
        pass

    @property
    def tenant_network_mask_bits(self):
        pass

    @property
    def user_domain_id(self):
        return self.get_keystone_credential("user_domain_name")

    @property
    def user_domain_name(self):
        pass

    @property
    def username(self):
        return self.get_keystone_credential("username")

    @property
    def volume_size(self):
        pass

    @property
    def vm_to_heat_api_insecure(self):
        return self.get_spec_item("ssl.public_endpoints.enabled", True)
