#    Copyright 2025 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import hashlib
import html.parser
import http.cookiejar
import ssl
import keystoneauth1

from time import perf_counter
from urllib import parse
from urllib import request

from prometheus_client.core import GaugeMetricFamily

from rockoon import utils
from rockoon.exporter import settings
from rockoon.exporter.collectors.openstack import base

LOG = utils.get_logger(__name__)


class HorizonHTMLParser(html.parser.HTMLParser):
    csrf_token = None
    region = None
    login = None

    def _find_name(self, attrs, name):
        for attrpair in attrs:
            if attrpair[0] == "name" and attrpair[1] == name:
                return True
        return False

    def _find_value(self, attrs):
        for attrpair in attrs:
            if attrpair[0] == "value":
                return attrpair[1]
        return None

    def _find_attr_value(self, attrs, attr_name):
        for attrpair in attrs:
            if attrpair[0] == attr_name:
                return attrpair[1]
        return None

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            if self._find_name(attrs, "csrfmiddlewaretoken"):
                self.csrf_token = self._find_value(attrs)
            if self._find_name(attrs, "region"):
                self.region = self._find_value(attrs)
        if tag == "form":
            self.login = self._find_attr_value(attrs, "action")


class OsdplHorizonMetricCollector(base.OpenStackBaseMetricCollector):
    _name = "osdpl_horizon"
    _description = "OpenStack Dashboard service metrics"
    _os_service_types = ["dashboard"]

    def __init__(self):
        self._opener = None
        self.ca_cert_checksum = None
        self.cookie_jar = http.cookiejar.CookieJar()
        super().__init__()

    # Override base property. The 'dashboard' service is not listed in identity services
    @property
    def is_service_available(self):
        try:
            list(self.oc.oc.identity.services())
        except keystoneauth1.exceptions.http.Unauthorized:
            LOG.warning("Unauthorized. Resetting OpenStack client.")
            self._oc = None
        finally:
            return True

    @utils.timeit
    def init_families(self):
        return {
            "login_success": GaugeMetricFamily(
                f"{self._name}_login_success",
                "Horizon UI login success status",
                labels=[
                    "url",
                    "username",
                    "user_domain_name",
                    "authentication_method",
                ],
            ),
            "login_latency": GaugeMetricFamily(
                f"{self._name}_login_latency",
                "Horizon UI login latency in seconds",
                labels=[
                    "url",
                    "type",
                ],
            ),
        }

    def get_credentials(self):
        config = self.oc.oc.config.auth
        return {
            "username": config.get("username"),
            "password": config.get("password"),
            "user_domain_name": config.get("user_domain_name"),
            "authentication_method": "Keystone Credentials",
        }

    @property
    def dashboard_url(self):
        public_domain_name = self.osdpl.mspec["public_domain_name"]
        return f"https://horizon.{public_domain_name}/"

    # TODO(dbiletskyi): Decrease timeout after PRODX-55176 is fixed
    def check_login_page(self, opener, dashboard_url, timeout=30):
        start_time = perf_counter()
        response = opener.open(dashboard_url, timeout=timeout).read()
        if "id_username" not in response.decode("utf-8"):
            raise ValueError("Cannot find 'id_username' in login page")
        end_time = perf_counter()
        return end_time - start_time

    def check_user_login(self, opener, dashboard_url, credentials, timeout=30):
        start_time = perf_counter()
        response = opener.open(dashboard_url, timeout=timeout).read()

        # Grab the CSRF token and default region
        parser = HorizonHTMLParser()
        parser.feed(response.decode("utf-8"))

        # construct login url for dashboard, discovery accommodates non-/ web
        # root for dashboard
        login_url = parse.urljoin(dashboard_url, parser.login)

        # Prepare login form request
        req = request.Request(login_url)
        req.add_header("Content-type", "application/x-www-form-urlencoded")
        req.add_header("Referer", dashboard_url)

        params = {
            "username": credentials["username"],
            "password": credentials["password"],
            "region": parser.region,
            "domain": credentials["user_domain_name"],
            "csrfmiddlewaretoken": parser.csrf_token,
        }
        opener.open(req, parse.urlencode(params).encode(), timeout=timeout)

        response = opener.open(dashboard_url, timeout=timeout).read()
        if "Overview" not in response.decode("utf-8"):
            raise ValueError("Cannot find 'Overview' in home page")
        end_time = perf_counter()
        return end_time - start_time

    @property
    def opener(self):
        with open(settings.OSCTL_EXPORTER_CA_CERT_PATH, "rb") as f:
            current_checksum = hashlib.sha256(f.read()).hexdigest()
        if self.ca_cert_checksum == current_checksum and self._opener:
            return self._opener

        self.ca_cert_checksum = current_checksum
        ctx = ssl.create_default_context(
            cafile=settings.OSCTL_EXPORTER_CA_CERT_PATH
        )
        self._opener = request.build_opener(
            request.HTTPSHandler(context=ctx),
            request.HTTPCookieProcessor(self.cookie_jar),
        )
        return self._opener

    @utils.timeit
    def update_login_samples(self):
        login_success_status = 0
        login_latency_samples = []
        try:
            self.cookie_jar.clear()
            opener = self.opener
            credentials = self.get_credentials()
            dashboard_url = self.dashboard_url
            login_page_latency = self.check_login_page(opener, dashboard_url)
            login_latency_samples.append(
                (
                    [
                        dashboard_url,
                        "login_page",
                    ],
                    login_page_latency,
                )
            )
            login_success_latency = self.check_user_login(
                opener, dashboard_url, credentials
            )
            login_latency_samples.append(
                (
                    [
                        dashboard_url,
                        "login_success",
                    ],
                    login_success_latency,
                )
            )
            login_success_status = 1
        except Exception as e:
            LOG.error(f"Dashboard UI check failed: {e}")

        self.set_samples(
            "login_success",
            [
                (
                    [
                        dashboard_url,
                        credentials["username"],
                        credentials["user_domain_name"],
                        credentials["authentication_method"],
                    ],
                    login_success_status,
                )
            ],
        )

        self.set_samples("login_latency", login_latency_samples)

    @utils.timeit
    def update_samples(self):
        self.update_login_samples()
