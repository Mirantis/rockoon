from rockoon.filters.tempest import base_section


class Default(base_section.BaseSection):
    name = "DEFAULT"
    options = [
        "debug",
        "log_config_append",
        "log_date_format",
        "log_file",
        "log_dir",
        "watch_log_file",
        "use_syslog",
        "use_journal",
        "syslog_log_facility",
        "use_json",
        "use_stderr",
        "logging_context_format_string",
        "logging_default_format_string",
        "logging_debug_format_suffix",
        "logging_exception_prefix",
        "logging_user_identity_format",
        "default_log_levels",
        "publish_errors",
        "instance_format",
        "instance_uuid_format",
        "rate_limit_interval",
        "rate_limit_burst",
        "rate_limit_except_level",
        "fatal_deprecations",
        "resources_prefix",
        "pause_teardown",
    ]

    @property
    def debug(self):
        pass

    @property
    def log_config_append(self):
        pass

    @property
    def log_date_format(self):
        pass

    @property
    def log_file(self):
        pass

    @property
    def log_dir(self):
        pass

    @property
    def watch_log_file(self):
        pass

    @property
    def use_syslog(self):
        pass

    @property
    def use_journal(self):
        pass

    @property
    def syslog_log_facility(self):
        pass

    @property
    def use_json(self):
        pass

    @property
    def use_stderr(self):
        pass

    @property
    def logging_context_format_string(self):
        pass

    @property
    def logging_default_format_string(self):
        pass

    @property
    def logging_debug_format_suffix(self):
        pass

    @property
    def logging_exception_prefix(self):
        pass

    @property
    def logging_user_identity_format(self):
        pass

    @property
    def default_log_levels(self):
        pass

    @property
    def publish_errors(self):
        pass

    @property
    def instance_format(self):
        pass

    @property
    def instance_uuid_format(self):
        pass

    @property
    def rate_limit_interval(self):
        pass

    @property
    def rate_limit_burst(self):
        pass

    @property
    def rate_limit_except_level(self):
        pass

    @property
    def fatal_deprecations(self):
        pass

    @property
    def resources_prefix(self):
        pass

    @property
    def pause_teardown(self):
        pass
