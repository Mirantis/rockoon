from rockoon.filters.tempest import base_section


class Validation(base_section.BaseSection):
    name = "validation"
    options = [
        "auth_method",
        "connect_method",
        "connect_timeout",
        "floating_ip_range",
        "image_ssh_password",
        "image_ssh_user",
        "image_alt_ssh_password",
        "image_alt_ssh_user",
        "ip_version_for_ssh",
        "network_for_ssh",
        "ping_count",
        "ping_size",
        "ping_timeout",
        "run_validation",
        "security_group",
        "security_group_rules",
        "ssh_shell_prologue",
        "ssh_timeout",
    ]

    @property
    def auth_method(self):
        pass

    @property
    def connect_method(self):
        pass

    @property
    def connect_timeout(self):
        pass

    @property
    def floating_ip_range(self):
        pass

    @property
    def image_ssh_password(self):
        pass

    @property
    def image_ssh_user(self):
        pass

    @property
    def image_alt_ssh_password(self):
        pass

    @property
    def image_alt_ssh_user(self):
        pass

    @property
    def ip_version_for_ssh(self):
        pass

    @property
    def network_for_ssh(self):
        pass

    @property
    def ping_count(self):
        pass

    @property
    def ping_size(self):
        pass

    @property
    def ping_timeout(self):
        pass

    @property
    def run_validation(self):
        pass

    @property
    def security_group(self):
        pass

    @property
    def security_group_rules(self):
        pass

    @property
    def ssh_shell_prologue(self):
        pass

    @property
    def ssh_timeout(self):
        pass
