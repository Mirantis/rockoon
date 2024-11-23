from rockoon.constants import OpenStackVersion
from rockoon.filters.tempest import base_section


class IdentityFeatureEnabled(base_section.BaseSection):
    name = "identity-feature-enabled"
    options = [
        "api_extensions",
        "api_v2",
        "api_v2_admin",
        "api_v3",
        "application_credentials",
        "domain_specific_drivers",
        "forbid_global_implied_dsr",
        "security_compliance",
        "trust",
    ]

    @property
    def api_extensions(self):
        pass

    @property
    def api_v2(self):
        """API version 2 is not supported anymore"""
        return False

    @property
    def api_v2_admin(self):
        """API version 2 is not supported anymore"""
        return False

    @property
    def api_v3(self):
        pass

    @property
    def application_credentials(self):
        # ['external', 'password', 'token', 'oauth1', 'mapped', 'application_credential']
        # These default values from upstream
        # https://opendev.org/openstack/keystone/src/branch/stable/stein/keystone/conf/constants.py
        return "application_credential" in self.get_values_item(
            "keystone",
            "conf.keystone.auth.methods",
            (
                "external",
                "password",
                "token",
                "oauth1",
                "mapped",
                "application_credential",
            ),
        )

    @property
    def domain_specific_drivers(self):
        pass

    @property
    def forbid_global_implied_dsr(self):
        pass

    @property
    def security_compliance(self):
        """
        For now, we do not enable security compliance by default, or provide an easy
        mechanism to enable it
        """
        return False

    @property
    def trust(self):
        pass

    @property
    def access_rules(self):
        """
        Access rules for application credentials were added in the Train release
        """
        if (
            OpenStackVersion[self.spec["openstack_version"]]
            >= OpenStackVersion["train"]
        ):
            return True
        return False
