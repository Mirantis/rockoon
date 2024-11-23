from rockoon.filters.tempest import base_section


class PatrolePlugin(base_section.BaseSection):
    name = "patrole"
    options = [
        "enable_rbac",
        "rbac_test_role",
        "custom_policy_files",
        "test_custom_requirements",
        "custom_requirements_file",
    ]

    @property
    def enable_rbac(self):
        return False

    @property
    def rbac_test_role(self):
        pass

    @property
    def custom_policy_files(self):
        pass

    @property
    def test_custom_requirements(self):
        pass

    @property
    def custom_requirements_file(self):
        pass
