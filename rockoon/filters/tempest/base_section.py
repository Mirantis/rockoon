import abc
import operator
from jsonpath_ng import parse

from rockoon import constants


class BaseSection(object):
    def __init__(self, spec, helmbundles_body):
        super(BaseSection, self).__init__()
        self.spec = spec
        self.helmbundles_body = helmbundles_body

    @abc.abstractproperty
    def name(self):
        """ """

    @abc.abstractproperty
    def options(self):
        """ """

    @abc.abstractproperty
    def enabled(self):
        """Flag to add section into config

        :returns True: When section should be added to config
        :returns False: When section is not needed for example when service
                        is not enabled at all.
        """
        return True

    def tf_enabled(self):
        try:
            if self.spec["features"]["neutron"]["backend"] == "tungstenfabric":
                return True
        except:
            pass

    def get_values_item(self, service_name, item_path, item_default=None):
        for component_name, component in self.helmbundles_body.items():
            for release in component.get("spec", {}).get("releases", []):
                chart_name = release["chart"]
                if chart_name == service_name:
                    res = parse(item_path).find(release["values"])
                    if res:
                        return res[0].value
                    else:
                        return item_default

    def get_spec_item(self, item_path, item_default=None):
        res = parse(item_path).find(self.spec)
        if res:
            return res[0].value
        else:
            return item_default

    def get_keystone_credential(self, cred_name):
        if self.is_service_enabled("keystone"):
            return self.get_values_item(
                "keystone", f"endpoints.identity.auth.admin.{cred_name}"
            )

    def is_service_enabled(self, service):
        """Check if service is enabled in specific environment.

        We assume service is enabled when API for this serivce is
        enabled at least on one node in the cloud.

        :param service:
        :param pillars:
        """
        for component_name, component in self.helmbundles_body.items():
            for release in component.get("spec", {}).get("releases", []):
                chart_name = release["chart"]
                if chart_name == service:
                    return True
        return False

    def os_version_compare(self, version, expression):
        """Compare OpenStack versions based on expression

        version: OpenStack version
        expression: valid math expression
        """
        return getattr(operator, expression)(
            constants.OpenStackVersion[self.spec["openstack_version"]],
            constants.OpenStackVersion[version],
        )
