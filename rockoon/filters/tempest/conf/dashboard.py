from rockoon.filters.tempest import base_section


class Dashboard(base_section.BaseSection):
    name = "dashboard"
    options = [
        "dashboard_url",
        "login_url",
        "disable_ssl_certificate_validation",
    ]

    @property
    def dashboard_url(self):
        pass

    @property
    def login_url(self):
        pass

    @property
    def disable_ssl_certificate_validation(self):
        ssl_cacert_enabled = self.get_values_item(
            "horizon",
            "conf.horizon.local_settings.config.ssl_features.openstack_ssl_cacert.enabled",
            False,
        )
        if not ssl_cacert_enabled:
            return True
        return False
