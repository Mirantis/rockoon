import base64
import configparser

from rockoon.tests.functional import base
from rockoon import settings
from rockoon import kube


class SecretsContentFunctionalTestCase(base.BaseFunctionalTestCase):
    def setUp(self):
        super().setUp()
        # Sections we should not check
        self.skip_sections = ["ironic"]
        # Keys we should not check
        self.skip_keys = ["auth_type", "OS_AUTH_TYPE"]
        # Secret names we should not check
        self.skip_secrets = [
            "keystone-fernet-data",
            "ingress-openstack",
            "ingress-openstack-nginx",
            "ingress-openstack-openstack-ingress-nginx",
            "openstack-mariadb-openstack-mariadb-mariadb-ingress",
            "openstack-mariadb-mariadb-state",
        ]

    def check_secret_field(self, data):
        """Check 'password' value in secret data

        :param data: str with decoded data of secret
        :return: (bool) false if config contains value 'password'
        :return: (bool) false if config contains values as
                 '=password', ':password@', ':"password"'
        """
        try:
            parser = configparser.ConfigParser(
                interpolation=None, strict=False
            )
            # Try to read config via configparser.
            # With it we can skip sections.
            parser.read_string(data)

            for section in parser.sections():
                for k, v in parser.items(section):
                    if (
                        v == "password"
                        and section not in self.skip_sections
                        and k not in self.skip_keys
                    ):
                        return False
        except configparser.MissingSectionHeaderError:
            data = data.replace(" ", "")

            # Password may contains as:
            # 1. Option of config file
            # 2. Part of URL in config files
            # 3. In generated passwords
            values_to_check = ["=password", ":password@", ':"password"']
            contains_password = any(value in data for value in values_to_check)

            if "password" == data or contains_password:
                return False
        return True

    def test_secret_does_not_contain_default_password(self):
        errors = []
        for secret in kube.Secret.objects(self.kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE
        ):
            if secret.name in self.skip_secrets:
                continue
            for key, value in secret.obj.get("data", {}).items():
                if key in self.skip_keys:
                    continue
                data = base64.b64decode(value).decode("utf-8")
                if not self.check_secret_field(data):
                    errors.append((secret.name, key, data))
        self.assertEqual(
            [], errors, f"Some secrets has default passwords: {errors}"
        )
