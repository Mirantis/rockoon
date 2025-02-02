from rockoon import constants
from rockoon import kube
import json
import os
import pykube


class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class Config(metaclass=SingletonMeta):
    def __init__(self):
        self._osdpl = kube.get_osdpl()

        self.LOG_PATH = os.getenv(
            "LOG_PATH", "/var/lib/tests/parallel/pytest.log"
        )
        self.CIRROS_TEST_IMAGE_NAME = self.get_cirros_image()
        self.UBUNTU_TEST_IMAGE_NAME = "Ubuntu-18.04"
        self.TEST_FLAVOR_SMALL_NAME = "m1.small"
        self.TEST_FLAVOR_NAME = "m1.extra_tiny_test"
        self.TEST_SUBNET_RANGE = "10.20.30.0/24"
        self.TEST_SUBNET_RANGE_ALT = "10.20.31.0/24"
        self.TEST_IPV6_SUBNET_RANGE = "2001:db8::/48"
        self.TEST_LB_SUBNET_RANGE = "192.168.0.0/24"
        self.PUBLIC_NETWORK_NAME = "public"
        self.EXTERNAL_ROUTER = "r1"

        # Time in seconds to wait for a compute operation to complete. Default is 120 seconds.
        self.COMPUTE_TIMEOUT = 60 * 2
        # Interval in seconds to check the status of a compute resource. Default is 1 second.
        self.COMPUTE_BUILD_INTERVAL = 1

        # Time in seconds to wait for a metric value. Default is 30 seconds.
        self.METRIC_TIMEOUT = 45
        # Interval in seconds to check the metric value. Default is 1 second.
        self.METRIC_INTERVAL_TIMEOUT = 5

        # Time in seconds to wait for a volume operation to complete. Default is 60 seconds.
        self.VOLUME_TIMEOUT = 30 * 2
        # Interval in seconds to check the status of a compute resource. Default is 1 second.
        self.VOLUME_BUILD_INTERVAL = 1

        # Time in seconds to wait for a server to change a status. Default is 60 seconds.
        self.SERVER_TIMEOUT = 60
        # Interval in seconds to check the server status. Default is 1 second.
        self.SERVER_READY_INTERVAL = 1

        # Time in seconds to wait for a baremetal node operation to complete. Default is 60 seconds.
        self.BAREMETAL_NODE_TIMEOUT = 60

        # Time in seconds to wait for a volume create. Default is 30 seconds. Small volume is cirros based (up to 100Mb)
        self.VOLUME_SMALL_CREATE_TIMEOUT = 30
        # Time in seconds to wait for a volume create. Default is 30 seconds. Medium volume is Ubuntu based (up to 1Gb)
        self.VOLUME_MEDIUM_CREATE_TIMEOUT = 300
        # Interval in seconds to check the volume status. Default is 1 second.
        self.VOLUME_READY_INTERVAL = 1
        # Size, in GB of the volume to create.
        self.VOLUME_SIZE = 1
        # Time in seconds to wait for a cinder pool timestamp updated
        self.CINDER_POOL_UPDATE_TIMEOUT = 120
        # Interval in seconds to check the cinder pool timestamp
        self.CINDER_POOL_UPDATE_INTERVAL = 3

        # The Neutron PortProber exporter port
        self.PORTPROBER_EXPORTER_PORT = 8000

        # Time in seconds to wait for metric update. Is the period how often probber sends metrics.
        # prometheus scrape inteval 20 + 2 x cloudprober probe interval 15 + file surfacer update timeout 10
        self.PORTPROBER_PROBE_INTERVAL = 60

        # Time in seconds to wait for metric to appear. The cloudprober refreshes targets priodically,
        # so wait while metrics appear in cloudprober.
        # PORTPROBER_PROBE_INTERVAL + cloudprober file check interval 30
        self.PORTPROBER_METRIC_REFRESH_TIMEOUT = (
            self.PORTPROBER_PROBE_INTERVAL + 30
        )

        self.PORTPROBER_METRIC_TIMEOUT = (
            self.PORTPROBER_PROBE_INTERVAL
            + self.PORTPROBER_METRIC_REFRESH_TIMEOUT
        )

        # Number of portprober agents to host nework
        self.PORTPROBER_AGENTS_PER_NETWORK = 2

        # Number of DHCP agents to host nework
        self.DHCP_AGENTS_PER_NETWORK = 2

        # Size, in GB of the flavor's disk to create.
        self.FLAVOR_DISK_SIZE = 1
        # Size, in MB of the flavor's ram to create.
        self.FLAVOR_RAM_SIZE = 256

        self.SERVER_LIVE_MIGRATION_TIMEOUT = 750
        self.NODE_LOAD_STABILIZATION_TIMEOUT = 1200
        self.NODE_LOAD_ABS_DIFFERENCE = 15

        self.DRB_CONFIG_NAMESPACE = "openstack"
        self.STABLE_NODE_LOAD = 40
        self.STACKLIGHT_GRAFANA_HOST = "http://grafana.stacklight"
        self.GRAFANA_MAX_RETRIES = 3
        self.GRAFANA_RETRY_INTERVAL = 10

        # Interval in seconds to wait for a loadbalancer operation. Default is 10 second.
        self.LB_OPERATION_INTERVAL = 10
        # Time in seconds to wait for a loadbalancer action is completed. Default is 300 second.
        self.LB_OPERATION_TIMEOUT = 300

        # Timeout in seconds to wait for port to become ACTIVE.
        self.PORT_TIMEOUT = 60
        # Interval in seconds to wait for port to become ACTIVE
        self.PORT_INTERVAL = 10

        self.FEDERATION_USERS = {
            "k1": {"username": "writer", "password": "password"},
            "k2": {"username": "writer2", "password": "password"},
        }

        # Timeout for handling nodemaintenancerequest operations
        # do not set to high, we have negative tests that will wait
        # for this timeout.
        self.NWL_STATE_TIMEOUT = 180

        self.MASAKARI_NOTIFICATION_TIMEOUT = 600

        configmap = kube.find(
            pykube.ConfigMap,
            "rockoon-functional-config",
            "osh-system",
            silent=True,
        )
        if configmap:
            for k, v in configmap.obj["data"].items():
                try:
                    val = json.loads(v)
                except:
                    val = v
                setattr(self, k, val)

    def get_cirros_image(self):
        openstack_version = self._osdpl.obj["spec"]["openstack_version"]
        if (
            constants.OpenStackVersion["xena"]
            >= constants.OpenStackVersion[openstack_version]
        ):
            return "Cirros-5.1"
        return "Cirros-6.0"
