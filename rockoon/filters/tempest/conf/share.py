from rockoon.filters.tempest import base_section


MICROVERSION_RELEASE_MAPPING = {
    "pike": {"min_api_microversion": "2.0", "max_api_microversion": "2.40"},
    "queens": {"min_api_microversion": "2.0", "max_api_microversion": "2.42"},
}

FEATURE_SUPPORT = {
    "lvm": {
        "create_delete_share": "mitaka",
        "manage_unmanage_share": "~",
        "extend_share": "mitaka",
        "shrink_share": "~",
        "create_delete_snapshot": "mitaka",
        "create_share_from_snapshot": "mitaka",
        "manage_unmanage_snapshot": "~",
        "revert_to_snapshot": "ocata",
        "mountable_snapshot": "ocata",
    },
    "glusterfs": {
        "create_delete_share": "juno",
        "manage_unmanage_share": "~",
        "extend_share": "~",
        "shrink_share": "~",
        "create_delete_snapshot": "liberty",
        "create_share_from_snapshot": "liberty",
        "manage_unmanage_snapshot": "~",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
    },
    "nexentastor4": {
        "create_delete_share": "newton",
        "manage_unmanage_share": "~",
        "extend_share": "newton",
        "shrink_share": "~",
        "create_delete_snapshot": "newton",
        "create_share_from_snapshot": "newton",
        "manage_unmanage_snapshot": "~",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
    },
    "nexentastor5": {
        "create_delete_share": "newton",
        "manage_unmanage_share": "~",
        "extend_share": "newton",
        "shrink_share": "newton",
        "create_delete_snapshot": "newton",
        "create_share_from_snapshot": "newton",
        "manage_unmanage_snapshot": "~",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
    },
}

ACCESS_RULES = {
    "lvm": {
        "ipv4": {"release": "mitaka", "protocols": "nfs"},
        "ipv6": {"release": "pike", "protocols": "nfs"},
        "user": {"release": "mitaka", "protocols": "cifs"},
    },
    "glusterfs": {
        "ipv4": {"release": "juno", "protocols": "nfs"},
        "ipv6": {"release": "~", "protocols": ""},
        "user": {"release": "~", "protocols": ""},
    },
    "nexentastor4": {
        "ipv4": {"release": "newton", "protocols": "nfs"},
        "ipv6": {"release": "~", "protocols": ""},
        "user": {"release": "~", "protocols": ""},
    },
    "nexentastor5": {
        "ipv4": {"release": "newton", "protocols": "nfs"},
        "ipv6": {"release": "~", "protocols": ""},
        "user": {"release": "~", "protocols": ""},
    },
}

COMMON_CAPABILITIES = {
    "lvm": {
        "dedupe": "~",
        "compression": "~",
        "thin_provisioning": "~",
        "thick_provisioning": "mitaka",
        "qos": "~",
        "create_share_from_snapshot": "kilo",
        "revert_to_snapshot": "ocata",
        "mountable_snapshot": "ocata",
        "ipv4_support": "pike",
        "ipv6_support": "pike",
    },
    "glusterfs": {
        "dedupe": "~",
        "compression": "~",
        "thin_provisioning": "~",
        "thick_provisioning": "liberty",
        "qos": "~",
        "create_share_from snapshot": "liberty",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
        "ipv4_support": "pike",
        "ipv6_support": "~",
    },
    "nexentastor4": {
        "dedupe": "newton",
        "compression": "newton",
        "thin_provisioning": "newton",
        "thick_provisioning": "newton",
        "qos": "~",
        "create_share_from_snapshot": "newton",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
        "ipv4_support": "pike",
        "ipv6_support": "~",
    },
    "nexentastor5": {
        "dedupe": "newton",
        "compression": "newton",
        "thin_provisioning": "newton",
        "thick_provisioning": "newton",
        "qos": "~",
        "create_share_from_snapshot": "newton",
        "revert_to_snapshot": "~",
        "mountable_snapshot": "~",
        "ipv4_support": "newton",
        "ipv6_support": "~",
    },
}


class Share(base_section.BaseSection):
    name = "share"
    options = [
        "backend_names",
        "capability_create_share_from_snapshot_support",
        "capability_storage_protocol",
        "default_share_type_name",
        "enable_ip_rules_for_protocols",
        "enable_user_rules_for_protocols",
        "enable_protocols",
        "max_api_microversion",
        "min_api_microversion",
        "multitenancy_enabled",
        "multi_backend",
        "run_ipv6_tests",
        "run_mount_snapshot_tests",
        "run_migration_with_preserve_snapshots_tests",
        "run_driver_assisted_migration_tests",
        "run_host_assisted_migration_tests",
        "run_replication_tests",
        "run_manage_unmanage_snapshot_tests",
        "run_manage_unmanage_tests",
        "run_share_group_tests",
        "run_revert_to_snapshot_tests",
        "run_snapshot_tests",
        "run_shrink_tests",
        "run_quota_tests",
        "suppress_errors_in_cleanup",
        "share_creation_retry_number",
        "client_vm_flavor_ref",
        "image_with_share_tools",
        "image_password",
        "catalog_type",
    ]

    @property
    def backend_names(self):
        pass

    @property
    def capability_create_share_from_snapshot_support(self):
        pass

    @property
    def capability_storage_protocol(self):
        pass

    @property
    def default_share_type_name(self):
        pass

    @property
    def enable_ip_rules_for_protocols(self):
        pass

    @property
    def enable_user_rules_for_protocols(self):
        pass

    @property
    def enable_protocols(self):
        enabled_protocols = self.get_values_item(
            "manila", "conf.manila.DEFAULT.enabled_share_protocols"
        )
        if enabled_protocols:
            return enabled_protocols.lower()

    @property
    def multitenancy_enabled(self):
        pass

    @property
    def multi_backend(self):
        pass

    @property
    def max_api_microversion(self):
        pass

    @property
    def min_api_microversion(self):
        pass

    @property
    def run_ipv6_tests(self):
        pass

    @property
    def run_mount_snapshot_tests(self):
        pass

    @property
    def run_migration_with_preserve_snapshots_tests(self):
        pass

    @property
    def run_driver_assisted_migration_tests(self):
        pass

    # Defines whether to run host-assisted migration tests or not
    @property
    def run_host_assisted_migration_tests(self):
        pass

    @property
    def run_replication_tests(self):
        pass

    @property
    def run_manage_unmanage_snapshot_tests(self):
        pass

    @property
    def run_manage_unmanage_tests(self):
        pass

    # Defines whether to run share group tests or not
    @property
    def run_share_group_tests(self):
        pass

    @property
    def run_revert_to_snapshot_tests(self):
        pass

    @property
    def run_snapshot_tests(self):
        pass

    @property
    def run_shrink_tests(self):
        pass

    @property
    def run_quota_tests(self):
        pass

    # Defines number of retries for share creation.
    @property
    def share_creation_retry_number(self):
        pass

    # Whether to suppress errors with clean up operation or not.
    @property
    def suppress_errors_in_cleanup(self):
        pass

    # Defines client vm flavor reference.
    @property
    def client_vm_flavor_ref(self):
        pass

    # Defines name of image with share tools.
    @property
    def image_with_share_tools(self):
        return "manila-service-image"

    # Defines password for image with share tools.
    @property
    def image_password(self):
        pass

    # Defines catalog type for tests
    @property
    def catalog_type(self):
        return "sharev2"
