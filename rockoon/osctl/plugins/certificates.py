#!/usr/bin/env python3
import sys
import time

from rockoon.osctl.plugins import base
from rockoon.osctl import settings
from rockoon import kube
from rockoon import utils
from rockoon import osdplstatus
from rockoon import health
from rockoon import resource_view

LOG = utils.get_logger(__name__)


class CertificatesShell(base.OsctlShell):
    name = "certificates"
    description = "Manage certificates of OpenStack deployment."

    def build_options(self):
        certificates_sub = self.pl_parser.add_subparsers(
            dest="sub_subcommand", required=True
        )

        rotation_parser = certificates_sub.add_parser(
            "rotate", help="Trigger OpenStack deployment certificate rotation"
        )
        rotation_parser.add_argument(
            "--osdpl",
            required=True,
            type=str,
            help="Name of OpenstackDeployment object",
        )
        rotation_parser.add_argument(
            "--namespace",
            default=settings.OSDPL_NAMESPACE,
            type=str,
            help="Name of OpenstackDeployment object namespace",
        )
        rotation_parser.add_argument(
            "--type",
            required=True,
            action="append",
            choices=settings.CERTIFICATE_ROTATION_CHOICES_LIST,
            help="Service and component of certificates to rotate. Use multiple --type service:component options for more than one.",
        )
        rotation_parser.add_argument(
            "--wait", required=False, default=False, action="store_true"
        )

    def rotate(self, args):
        certs_groups = set(args.type)
        osdpl = kube.find(
            kube.OpenStackDeployment, args.osdpl, args.namespace, silent=True
        )
        if not osdpl:
            LOG.error(
                f"The OpenStackDeployment {args.namespace}/{args.osdpl} was not found!"
            )
            sys.exit(1)
        osdpl.reload()

        rotation_id = {}
        for certs_group in certs_groups:
            service, component = certs_group.split(":")
            rotation_id[certs_group] = (
                utils.get_in(
                    osdpl.obj,
                    [
                        "status",
                        "certificates",
                        service,
                        component,
                        "rotation_id",
                    ],
                    0,
                )
                + 1
            )

        LOG.info(f"Starting certificate rotation for {certs_groups}")
        patch = {"status": {"certificates": {}}}
        for certs_group in certs_groups:
            service, component = certs_group.split(":")
            patch["status"]["certificates"].setdefault(service, {})[
                component
            ] = {"rotation_id": rotation_id[certs_group]}

        osdpl.patch(patch, subresource="status")
        LOG.info(
            f"Started certificate rotation for {certs_groups}, please wait for OpenstackDeployment status becoming APPLIED."
        )

        if args.wait is True:
            LOG.info(f"Waiting rotation changes are applied")
            osdplst = osdplstatus.OpenStackDeploymentStatus(
                args.osdpl, args.namespace
            )
            child_view = resource_view.ChildObjectView(osdpl.mspec)
            while True:
                if osdplst.get_osdpl_status() == osdplstatus.APPLYING:
                    break
                time.sleep(10)
            while True:
                if osdplst.get_osdpl_status() == osdplstatus.APPLIED:
                    LOG.info(f"Waiting openstack services are healthy.")
                    health.wait_services_healthy(
                        osdpl.mspec, osdplst, child_view
                    )
                    break
                time.sleep(10)
