import logging
import exec_helpers
import paramiko

from kombu import Connection
from unittest import TestCase
from retry import retry
from io import StringIO
from paramiko.ssh_exception import NoValidConnectionsError, SSHException

import openstack
from rockoon import kube
from rockoon import layers
from rockoon import openstack_utils
from rockoon import settings
from rockoon.exporter import constants
from rockoon.tests.functional import config
from rockoon.tests.functional import waiters, data_utils

CONF = config.Config()

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "context": {
            "format": "%(asctime)s %(levelname)s %(testMethodName)s %(name)s (%(filename)s:%(lineno)s) %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": CONF.LOG_PATH,
            "formatter": "context",
        },
    },
    "loggers": {
        "aiohttp": {
            "level": "WARNING",
        },
        "stevedore": {
            "level": "INFO",
        },
        "urllib3": {
            "level": "INFO",
        },
        "pykube": {
            "level": "INFO",
        },
    },
    "root": {
        "handlers": ["default", "file"],
        "level": "DEBUG",
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logging_old_factory = logging.getLogRecordFactory()
LOG = logging.getLogger(__name__)


def suppress404(func):
    def inner(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except openstack.exceptions.ResourceNotFound:
            pass

    return inner


class BaseFunctionalTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ocm = openstack_utils.OpenStackClientManager()
        cls.osdpl = kube.get_osdpl()
        cls.osdpl_spec = layers.substitude_osdpl(cls.osdpl.obj["spec"])

    def setUp(self):
        self.kube_api = kube.kube_client()
        self.logger = LOG
        self.setup_logging()
        super().setUp()

    def setup_logging(self):
        logging.setLogRecordFactory(self.logging_record_factory)

    def logging_record_factory(self, *args, **kwargs):
        record = logging_old_factory(*args, **kwargs)
        record.testMethodName = self._testMethodName
        return record

    @property
    def keystone_client_pod(self):
        pods = kube.Pod.objects(self.kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={"application": "keystone", "component": "client"},
        )
        return [x for x in pods][0]

    def libvirt_pod(self, host):
        kube_api = kube.kube_client()
        pods = kube.Pod.objects(kube_api).filter(
            namespace=settings.OSCTL_OS_DEPLOYMENT_NAMESPACE,
            selector={"application": "libvirt", "component": "libvirt"},
        )
        for pod in pods:
            if pod.obj["spec"].get("nodeName") == host:
                return pod

    @property
    def neutron_portprober_enabled(self):
        if self.ocm.oc.network.find_extension("portprober"):
            return True
        return False

    @classmethod
    def cronjob_run(cls, cronjob, wait=False):
        cron = kube.find(kube.CronJob, cronjob, namespace=cls.osdpl.namespace)
        job = cron.run()
        LOG.debug(f"Started job {job}")
        cls.addClassCleanup(cls.job_delete, job)
        if wait:
            try:
                waiters.wait_for_job_status(
                    job,
                    "ready",
                    600,
                    30,
                )
            finally:
                job_logs = cls.get_job_logs(job)
                for pod, pod_logs in job_logs.items():
                    for container, logs in pod_logs.items():
                        LOG.debug(f"""Job {job}/{pod}/{container} LOGS:
                                  {logs}
                            """)
        return job

    @classmethod
    def get_job_logs(self, job):
        logs = {}
        for pod in job.pods:
            logs[pod] = {}
            for container in pod.obj["spec"]["containers"]:
                try:
                    logs[pod][container["name"]] = pod.logs(
                        container=container["name"]
                    )
                except Exception as e:
                    LOG.warning(
                        f"Got exception {e} while getting logs from {pod}/{container['name']}"
                    )
        return logs

    @classmethod
    def is_service_enabled(cls, name):
        return name in cls.osdpl.obj["spec"].get("features", {}).get(
            "services", []
        )

    @classmethod
    def is_ovn_enabled(cls):
        return (
            cls.osdpl.obj["spec"]["features"]
            .get("neutron", {})
            .get("backend", None)
            == "ml2/ovn"
        )

    @classmethod
    def job_delete(cls, job, propagation_policy="Foreground"):
        job.delete(propagation_policy=propagation_policy)

    def check_rabbitmq_connection(
        self, username, password, host, port, vhost, ssl=False
    ):
        rabbitmq_url = f"amqp://{username}:{password}@{host}:{port}/{vhost}"
        connection = Connection(rabbitmq_url, ssl=ssl)
        try:
            LOG.info(f"Connecting to the: {rabbitmq_url}")
            connection.ensure_connection(max_retries=3)
            connection.channel()
            return True
        except Exception as e:
            LOG.error(f"Connection error. Error: {e}")
        finally:
            connection.release()

    @retry(
        (
            TimeoutError,
            NoValidConnectionsError,
            SSHException,
            ConnectionResetError,
        ),
        tries=5,
        delay=30,
    )
    def ssh_instance(self, ip, pkey):
        LOG.info(f"Attempt to connect to instance with ip: {ip}")
        pkey = StringIO(pkey)
        auth = exec_helpers.SSHAuth(
            username="ubuntu",
            password="",
            key=paramiko.rsakey.RSAKey.from_private_key(pkey),
        )
        ssh = exec_helpers.SSHClient(host=ip, port=22, auth=auth, verbose=True)
        ssh.sudo_mode = True
        return ssh

    @classmethod
    def server_create(
        cls,
        wait=True,
        name=None,
        flavorRef=None,
        imageRef=None,
        networks="none",
        availability_zone=None,
        host=None,
        config_drive=None,
        user_data=None,
        tags=None,
        metadata=None,
        keypair=None,
    ):

        kwargs = {"networks": networks}
        kwargs["name"] = name or data_utils.rand_name()
        if flavorRef is None:
            kwargs["flavorRef"] = cls.ocm.oc.compute.find_flavor(
                CONF.TEST_FLAVOR_NAME
            ).id
        else:
            kwargs["flavorRef"] = flavorRef
        if imageRef is None:
            kwargs["imageRef"] = cls.ocm.oc.get_image_id(
                CONF.CIRROS_TEST_IMAGE_NAME
            )
        else:
            kwargs["imageRef"] = imageRef
        if availability_zone:
            kwargs["availability_zone"] = availability_zone
        if host:
            kwargs["host"] = host
        if user_data:
            kwargs["user_data"] = user_data
        if config_drive:
            kwargs["config_drive"] = True
        if tags:
            kwargs["tags"] = tags
        if metadata:
            kwargs["metadata"] = metadata
        if keypair:
            kwargs["key_name"] = keypair
        server = cls.ocm.oc.compute.create_server(**kwargs)
        if wait is True:
            waiters.wait_for_server_status(cls.ocm, server, status="ACTIVE")
        server = cls.ocm.oc.get_server(server.id)
        cls.addClassCleanup(cls.server_delete, server)
        return server

    @classmethod
    @suppress404
    def server_delete(cls, server, wait=True):
        try:
            console_out = cls.ocm.oc.compute.get_server_console_output(
                server.id
            )
            LOG.debug(
                "Console output for server %s is %s", server.id, console_out
            )
        except Exception:
            pass
        return cls.ocm.oc.delete_server(server.id, wait=wait)

    def server_reset_state(self, server, status, wait=True):
        self.ocm.oc.compute.reset_server_state(server.id, status)
        if wait is True:
            waiters.wait_for_server_status(self.ocm, server, status=status)

    @classmethod
    def lb_bundle_create(
        cls,
        name=None,
    ):
        if name is None:
            name = data_utils.rand_name()
        network = cls.network_create()
        subnet = cls.subnet_create(
            cidr=CONF.TEST_LB_SUBNET_RANGE, network_id=network["id"]
        )
        lb = cls.ocm.oc.load_balancer.create_load_balancer(
            name=name,
            vip_network_id=network["id"],
            vip_subnet_id=subnet["id"],
        )
        cls.addClassCleanup(
            waiters.wait_resource_deleted,
            cls.ocm.oc.load_balancer.get_load_balancer,
            lb["id"],
            CONF.LB_OPERATION_TIMEOUT,
            CONF.LB_OPERATION_INTERVAL,
            "provisioning_status",
        )
        cls.addClassCleanup(
            cls.ocm.oc.load_balancer.delete_load_balancer, lb["id"]
        )
        cls.ocm.oc.load_balancer.wait_for_load_balancer(
            lb["id"],
            interval=CONF.LB_OPERATION_INTERVAL,
            wait=CONF.LB_OPERATION_TIMEOUT,
        )
        return lb

    @classmethod
    def lb_update(cls, lb_id, admin_state_up=True):
        lb = cls.ocm.oc.load_balancer.update_load_balancer(
            lb_id, admin_state_up=admin_state_up
        )
        cls.ocm.oc.load_balancer.wait_for_load_balancer(
            lb["id"],
            status="ACTIVE",
            interval=CONF.LB_OPERATION_INTERVAL,
            wait=CONF.LB_OPERATION_TIMEOUT,
        )

    @classmethod
    def network_create(
        cls, name=None, shared=None, external=None, provider_network_type=None
    ):
        if name is None:
            name = data_utils.rand_name()
        kwargs = {"name": name}
        if shared:
            kwargs["shared"] = shared
        if external:
            kwargs["router:external"] = external
        if provider_network_type:
            kwargs["provider_network_type"] = provider_network_type
        network = cls.ocm.oc.network.create_network(**kwargs)
        cls.addClassCleanup(cls.network_delete, network)
        return network

    @classmethod
    @suppress404
    def network_delete(cls, network):
        return cls.ocm.oc.network.delete_network(network)

    @classmethod
    def subnet_create(
        cls,
        cidr,
        network_id,
        ip_version=4,
        name=None,
        **kwargs,
    ):
        if name is None:
            name = data_utils.rand_name()
        subnet = cls.ocm.oc.network.create_subnet(
            name=name,
            cidr=cidr,
            network_id=network_id,
            ip_version=ip_version,
            **kwargs,
        )
        cls.addClassCleanup(cls.subnet_delete, subnet)
        return subnet

    @classmethod
    @suppress404
    def subnet_delete(cls, subnet):
        return cls.ocm.oc.network.delete_subnet(subnet)

    @classmethod
    def port_create(
        cls,
        network_id,
        name=None,
        wait=True,
        status="DOWN",
        fixed_ips=None,
        is_port_security_enabled=True,
        binding_vnic_type=None,
    ):
        if name is None:
            name = data_utils.rand_name()
        kwargs = {
            "name": name,
            "network_id": network_id,
            "is_port_security_enabled": is_port_security_enabled,
        }
        if fixed_ips:
            kwargs.update({"fixed_ips": fixed_ips})
        if binding_vnic_type:
            kwargs.update({"binding:vnic_type": binding_vnic_type})
        port = cls.ocm.oc.network.create_port(**kwargs)
        if wait is True:
            waiters.wait_for_port_status(cls.ocm, port, status=status)
        cls.addClassCleanup(cls.port_delete, port)
        return port

    @classmethod
    @suppress404
    def port_delete(cls, port):
        return cls.ocm.oc.network.delete_port(port)

    @classmethod
    def floating_ip_create(cls, network):
        fip = cls.ocm.oc.create_floating_ip(network=network)
        fip_id = fip["id"]
        cls.addClassCleanup(cls.floating_ip_delete, fip_id)
        return fip

    @classmethod
    @suppress404
    def floating_ip_delete(cls, fip_id):
        cls.ocm.oc.delete_floating_ip(fip_id)

    @classmethod
    def floating_ips_associated(cls):
        res = 0
        for fip in cls.ocm.oc.list_floating_ips():
            if fip.get("port_id") is not None:
                res += 1
        return res

    @classmethod
    def floating_ips_not_associated(cls):
        res = 0
        for fip in cls.ocm.oc.list_floating_ips():
            if fip.get("port_id") is None:
                res += 1
        return res

    @classmethod
    @suppress404
    def router_delete(cls, router_id):
        for port in cls.ocm.oc.network.ports(device_id=router_id):
            try:
                cls.ocm.oc.network.remove_interface_from_router(
                    router_id, port_id=port["id"]
                )
            except openstack.exceptions.ResourceNotFound:
                pass
        cls.ocm.oc.network.delete_router(router_id)

    @classmethod
    def router_create(cls, name=None, external_gateway_info=None):
        if name is None:
            name = data_utils.rand_name()
        kwargs = {"name": name}
        if external_gateway_info:
            kwargs["external_gateway_info"] = external_gateway_info

        router = cls.ocm.oc.network.create_router(**kwargs)
        cls.addClassCleanup(cls.router_delete, router["id"])
        return router

    @classmethod
    def routers_availability_zones(cls, availability_zones):
        routers = []
        for router in list(cls.ocm.oc.network.routers()):
            if router["availability_zones"][0] == availability_zones:
                routers.append(router)
        return routers

    @classmethod
    def network_bundle_create(cls, provider_network_type=None):
        """Create network bundle and return metadata

        Creates bundle of router, subnet, network connected to flaoting network.
        """
        res = {}
        network = cls.network_create(
            provider_network_type=provider_network_type
        )
        subnet = cls.subnet_create(
            cidr=CONF.TEST_SUBNET_RANGE, network_id=network["id"]
        )
        res["network"] = network
        res["subnet"] = subnet
        public_network = cls.ocm.oc.network.find_network(
            CONF.PUBLIC_NETWORK_NAME
        )
        router = cls.router_create(
            external_gateway_info={"network_id": public_network["id"]}
        )
        res["router"] = router
        cls.ocm.oc.network.add_interface_to_router(
            router["id"], subnet_id=subnet["id"]
        )

        return res

    @classmethod
    def consumer_allocation_delete(cls, csm_id):
        res = cls.ocm.oc.placement.delete(f"/allocations/{csm_id}")
        if not res.ok and res.status_code != 404:
            res.raise_for_status()

    @classmethod
    def consumer_allocation_create(cls, csm_id, rp_id, resources):
        # Can be used starting yoga
        microversion = 1.39
        allocation = {
            "consumer_id": csm_id,
            "data": {
                "user_id": cls.ocm.oc.current_user_id,
                "project_id": cls.ocm.oc.current_project_id,
                "consumer_generation": None,
                "consumer_type": "INSTANCE",
                "allocations": {rp_id: {"resources": resources}},
            },
        }
        res = cls.ocm.oc.placement.put(
            f"/allocations/{csm_id}",
            json=allocation["data"],
            microversion=microversion,
        )
        cls.addClassCleanup(cls.consumer_allocation_delete, csm_id)
        res.raise_for_status()
        return allocation

    @classmethod
    def volume_create(
        cls,
        size=None,
        name=None,
        image=None,
        availability_zone=None,
        wait=True,
        timeout=None,
    ):
        if name is None:
            name = data_utils.rand_name()
        if size is None:
            size = CONF.VOLUME_SIZE
        if timeout is None:
            timeout = CONF.VOLUME_TIMEOUT

        volume = cls.ocm.oc.volume.create_volume(
            size=size,
            name=name,
            image_id=image,
            availability_zone=availability_zone,
            wait=wait,
            timeout=timeout,
        )
        cls.addClassCleanup(cls.volume_delete, volume)
        if wait is True:
            waiters.wait_resource_field(
                cls.ocm.oc.block_storage.get_volume,
                volume.id,
                {"status": "available"},
                timeout,
                CONF.VOLUME_READY_INTERVAL,
            )
        return volume

    @classmethod
    @suppress404
    def volume_delete(cls, volume, wait=False):
        cls.ocm.oc.delete_volume(volume.id)
        if wait:
            waiters.wait_resource_deleted(
                cls.ocm.oc.get_volume, volume.id, CONF.VOLUME_TIMEOUT, 5
            )

    @classmethod
    def get_volumes_size(cls):
        """Calculate the total size of volumes in bytes."""
        total_bytes = 0
        for volume in cls.ocm.oc.volume.volumes(all_tenants=True):
            total_bytes += volume.size * constants.Gi
        return total_bytes

    @classmethod
    def volume_snapshot_create(
        cls,
        volume,
        name=None,
    ):
        if name is None:
            name = data_utils.rand_name()

        snapshot = cls.ocm.oc.create_volume_snapshot(
            volume.id,
        )
        cls.addClassCleanup(cls.snapshot_volume_delete, snapshot)
        return snapshot

    @classmethod
    def snapshot_volume_delete(cls, snapshot, wait=False):
        cls.ocm.oc.delete_volume_snapshot(snapshot.id)
        if wait:
            waiters.wait_resource_deleted(
                cls.ocm.oc.get_volume_snapshot,
                snapshot.id,
                CONF.VOLUME_TIMEOUT,
                5,
            )

    @classmethod
    def get_volume_snapshots_size(cls):
        """Calculate the total size of volume snapshots in bytes."""
        total_bytes = 0
        for snapshot in cls.ocm.oc.volume.snapshots(all_tenants=True):
            total_bytes += snapshot.size * constants.Gi
        return total_bytes

    @suppress404
    def aggregate_delete(self, name_or_id):
        self.ocm.oc.delete_aggregate(name_or_id)

    def aggregate_create(self, name, availability_zone=None):
        aggregate = self.ocm.oc.compute.create_aggregate(
            name=name, availability_zone=availability_zone
        )
        self.addCleanup(self.aggregate_delete, aggregate["id"])
        return aggregate

    @suppress404
    def aggregate_remove_host(self, name, host):
        self.ocm.oc.compute.remove_host_from_aggregate(name, host)

    @suppress404
    def aggregate_remove_hosts(self, name):
        aggregate = self.ocm.oc.compute.get_aggregate(name)
        for host in aggregate["hosts"]:
            self.ocm.oc.compute.remove_host_from_aggregate(
                aggregate["id"], host
            )

    def aggregate_add_host(self, name, host):
        self.ocm.oc.compute.add_host_to_aggregate(name, host)
        self.addCleanup(self.aggregate_remove_host, name, host)

    @classmethod
    def service_create(cls, name, type):
        service = cls.ocm.oc.identity.create_service(name=name, type=type)
        cls.addClassCleanup(cls.service_delete, service["id"])
        return service

    @classmethod
    def endpoint_create(cls, service_id, interface, url):
        endpoint = cls.ocm.oc.identity.create_endpoint(
            service_id=service_id, interface=interface, url=url
        )
        cls.addClassCleanup(cls.endpoint_delete, endpoint["id"])
        return endpoint

    @classmethod
    @suppress404
    def service_delete(cls, service_id):
        cls.ocm.oc.identity.delete_service(service_id)

    @classmethod
    @suppress404
    def endpoint_delete(cls, endpoint):
        cls.ocm.oc.identity.delete_endpoint(endpoint)

    @classmethod
    def create_domain(cls, name, enabled=False):
        domain = cls.ocm.oc.identity.create_domain(name=name, enabled=enabled)
        cls.addClassCleanup(cls.delete_domain, domain["id"])
        return domain

    @classmethod
    @suppress404
    def delete_domain(cls, domain_id):
        cls.ocm.oc.identity.delete_domain(domain_id)

    @classmethod
    def flavor_create(cls, name=None, disk=None, ram=None, vcpus=None):
        if name is None:
            name = data_utils.rand_name(postfix="flavor")
        if disk is None:
            disk = CONF.FLAVOR_DISK_SIZE
        if ram is None:
            ram = CONF.FLAVOR_RAM_SIZE
        if vcpus is None:
            vcpus = 1
        flavor = cls.ocm.oc.compute.create_flavor(
            name=name, disk=disk, ram=ram, vcpus=vcpus
        )
        cls.addClassCleanup(cls.delete_flavor, flavor["id"])
        return flavor

    @classmethod
    @suppress404
    def delete_flavor(cls, flavor_id):
        cls.ocm.oc.compute.delete_flavor(flavor_id)

    def update_image_property(self, image, properties):
        clean_properties = self.ocm.oc.image.get_image(image).properties
        properties.update(clean_properties)
        self.addCleanup(
            self.ocm.oc.image.update_image_properties, image, clean_properties
        )
        self.ocm.oc.image.update_image(image, properties=properties)

    @classmethod
    def baremetal_node_create(cls, name=None, driver="fake-hardware"):
        if name is None:
            name = data_utils.rand_name()
        node = cls.ocm.oc.baremetal.create_node(name=name, driver=driver)
        cls.addClassCleanup(cls.delete_baremetal_node, node["uuid"])
        return node

    @classmethod
    def baremetal_node_maintenance_set(cls, node_uuid):
        cls.ocm.oc.baremetal.set_node_maintenance(node_uuid)

    @classmethod
    def baremetal_node_set_provision_state(cls, node_uuid, state):
        cls.ocm.oc.baremetal.set_node_provision_state(node_uuid, state)

    @classmethod
    @suppress404
    def delete_baremetal_node(cls, node_uuid, wait=False):
        cls.ocm.oc.baremetal.delete_node(node_uuid)
        if wait:
            waiters.wait_resource_deleted(
                cls.ocm.oc.baremetal.get_node,
                node_uuid,
                CONF.BAREMETAL_NODE_TIMEOUT,
                5,
            )

    def get_ports_by_status(self, status):
        ports = []
        for port in self.ocm.oc.network.ports():
            if port["status"] == status:
                ports.append(port)
        return ports

    def get_volume_service_status(self, svc):
        service = self.ocm.volume_get_services(
            host=svc["host"], binary=svc["binary"]
        )
        return service[0]["status"]

    def get_compute_service_state(self, svc):
        service = self.ocm.oc.compute.find_service(name_or_id=svc["id"])
        return service["state"]

    def get_compute_service_status(self, svc):
        service = self.ocm.oc.compute.find_service(name_or_id=svc["id"])
        return service["status"]

    def get_neutron_agent_status(self, svc):
        agent = self.ocm.oc.network.get_agent(svc["id"])
        return agent["is_admin_state_up"]

    def get_cinder_pool_timestamp(self, pool_name):
        pool = [
            pl
            for pl in list(self.ocm.oc.volume.backend_pools())
            if pl["name"] == pool_name
        ]
        return pool[0]["capabilities"].get("timestamp")

    def get_portprober_agent(self, host=None):
        return list(
            self.ocm.oc.network.agents(
                host=host, binary="neutron-portprober-agent"
            )
        )

    def get_portprober_networks(self, agent_id):
        return self.ocm.oc.network.get(
            f"/agents/{agent_id}/portprober-networks"
        ).json()["networks"]

    def get_agents_hosting_portprober_network(self, network_id):
        res = []
        for agent in self.get_portprober_agent():
            agent_nets = self.get_portprober_networks(agent["id"])
            for network in agent_nets:
                if network["id"] == network_id:
                    res.append(agent)
                    break
        return res

    @classmethod
    def create_keypair(self, name=None, public_key=None, private_key=None):
        if name is None:
            name = data_utils.rand_name(postfix="keypair")
        kwargs = {"name": name}
        if public_key:
            kwargs["public_key"] = public_key
        if private_key:
            kwargs["private_key"] = private_key
        keypair = self.ocm.oc.compute.create_keypair(**kwargs)
        self.addClassCleanup(self.delete_keypair, keypair["name"])
        return keypair

    @classmethod
    @suppress404
    def delete_keypair(self, keypair_name):
        self.ocm.oc.compute.delete_keypair(keypair_name)

    @classmethod
    def update_floating_ip(self, floating_ip_id, port_id):
        self.ocm.oc.network.update_ip(
            floating_ip=floating_ip_id, port_id=port_id
        )

    @classmethod
    def add_interface_to_router(cls, router, subnet_id):
        cls.ocm.oc.network.add_interface_to_router(
            router=router, subnet_id=subnet_id
        )
        cls.addClassCleanup(
            cls.remove_interface_from_router, router, subnet_id
        )

    @classmethod
    def remove_interface_from_router(cls, router, subnet_id):
        cls.ocm.oc.network.remove_interface_from_router(
            router=router, subnet_id=subnet_id
        )

    @classmethod
    def wait_portprober_ports(cls, network_id):
        waiters.wait_for_network_portprober_ports(
            cls.ocm, network_id, CONF.PORTPROBER_AGENTS_PER_NETWORK
        )
