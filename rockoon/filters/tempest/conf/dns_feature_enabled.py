from rockoon.filters.tempest import base_section


DNS_FEATURES_RELEASE_MAPPING = {
    "yoga": {
        "api_admin": True,
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "victoria": {
        "api_admin": True,
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "stein": {
        "api_admin": True,
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "queens": {
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "pike": {
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "ocata": {
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "newton": {
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
    "mitaka": {
        "api_v1": False,
        "api_v2": True,
        "bug_1573141_fixed": True,
        "api_v2_quotas": True,
        "api_v2_root_recordsets": True,
    },
}


class DnsFeatureEnabled(base_section.BaseSection):
    name = "dns_feature_enabled"
    options = [
        "api_admin",
        "api_v1",
        "api_v1_servers",
        "api_v2",
        "api_v2_quotas",
        "api_v2_quotas_verify_project",
        "api_v2_root_recordsets",
        "bug_1573141_fixed",
        "notification_nova_fixed",
        "notification_neutron_floatingip",
    ]

    def _get_dns_release_feature(self, feature):
        return DNS_FEATURES_RELEASE_MAPPING.get(
            self.spec["openstack_version"], {}
        ).get(feature)

    @property
    def api_admin(self):
        return self._get_dns_release_feature("api_admin")

    @property
    def api_v1(self):
        return self._get_dns_release_feature("api_v1")

    @property
    def api_v1_servers(self):
        pass

    @property
    def api_v2(self):
        return self._get_dns_release_feature("api_v2")

    @property
    def api_v2_quotas(self):
        return self._get_dns_release_feature("api_v2_quotas")

    @property
    def api_v2_root_recordsets(self):
        return self._get_dns_release_feature("api_v2_root_recordsets")

    @property
    def bug_1573141_fixed(self):
        return self._get_dns_release_feature("bug_1573141_fixed")

    @property
    def api_v2_quotas_verify_project(self):
        return False

    @property
    def notification_nova_fixed(self):
        return True

    @property
    def notification_neutron_floatingip(self):
        return True
