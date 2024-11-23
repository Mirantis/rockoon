from rockoon.filters.tempest import base_section


class Identity(base_section.BaseSection):
    name = "identity"
    options = [
        "admin_domain_scope",
        "admin_role",
        "auth_version",
        "ca_certificates_file",
        "catalog_type",
        "default_domain_id",
        "disable_ssl_certificate_validation",
        "region",
        "uri",
        "uri_v3",
        "user_lockout_duration",
        "user_lockout_failure_attempts",
        "user_unique_last_password_count",
        "v2_admin_endpoint_type",
        "v2_public_endpoint_type",
        "v3_endpoint_type",
    ]

    @property
    def admin_domain_scope(self):
        pass

    @property
    def admin_role(self):
        if (
            self.spec["features"]
            .get("policies", {})
            .get("strict_admin", {})
            .get("enabled", False)
        ):
            return "service"

    @property
    def auth_version(self):
        return "v3"

    @property
    def ca_certificates_file(self):
        pass

    @property
    def catalog_type(self):
        pass

    @property
    def default_domain_id(self):
        pass

    @property
    def disable_ssl_certificate_validation(self):
        pass

    @property
    def region(self):
        return self.get_spec_item("region_name", "RegionOne")

    @property
    def uri(self):
        pass

    @property
    def uri_v3(self):
        pass

    @property
    def user_lockout_duration(self):
        pass

    @property
    def user_lockout_failure_attempts(self):
        pass

    @property
    def user_unique_last_password_count(self):
        pass

    @property
    def v2_admin_endpoint_type(self):
        pass

    @property
    def v2_public_endpoint_type(self):
        pass

    @property
    def v3_endpoint_type(self):
        pass
