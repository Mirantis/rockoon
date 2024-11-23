#!/usr/bin/env python3
import asyncio
import sys
import time

from rockoon.osctl.plugins import base
from rockoon import kube
from rockoon import utils
from rockoon import osdplstatus
from rockoon import health
from rockoon import resource_view

LOG = utils.get_logger(__name__)

OSDPL_NAMESPACE = "openstack"


class CredentialsShell(base.OsctlShell):
    name = "credentials"
    description = "Manage credentials of OpenStack deployment."

    def build_options(self):
        credentials_sub = self.pl_parser.add_subparsers(
            dest="sub_subcommand", required=True
        )

        rotation_parser = credentials_sub.add_parser(
            "rotate", help="Trigger openstack deployment credentials rotation"
        )
        rotation_parser.add_argument(
            "--osdpl",
            required=True,
            type=str,
            help="Name of OpenstackDeployment object",
        )
        rotation_parser.add_argument(
            "--namespace",
            default=OSDPL_NAMESPACE,
            type=str,
            help="Name of OpenstackDeployment object namespace",
        )
        rotation_parser.add_argument(
            "--type",
            required=True,
            action="append",
            choices=["admin", "service"],
            help="""Type of credentials to rotate.
                    Use `admin` to rotate admin credentials for keystone.
                    Use `service` to rotate  mysql/rabbitmq/keystone credentials. Can be specified multiple time.""",
        )
        rotation_parser.add_argument(
            "--wait", required=False, default=False, action="store_true"
        )

    def rotate(self, args):
        creds_groups = set(args.type)
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
        for creds_group in creds_groups:
            rotation_id[creds_group] = (
                utils.get_in(
                    osdpl.obj,
                    ["status", "credentials", creds_group, "rotation_id"],
                    0,
                )
                + 1
            )

        LOG.info(f"Starting rotation for {creds_groups}")
        patch = {
            "status": {
                "credentials": {
                    creds_group: {"rotation_id": rotation_id[creds_group]}
                    for creds_group in creds_groups
                }
            }
        }
        osdplst = osdplstatus.OpenStackDeploymentStatus(
            args.osdpl, args.namespace
        )

        osdpl.patch(patch, subresource="status")
        LOG.info(
            f"Started credential rotation for {creds_groups}, please wait for OpenstackDeployment status becoming APPLIED."
        )

        if args.wait is True:
            LOG.info(f"Waiting rotation changes are applied")
            osdplst = osdplstatus.OpenStackDeploymentStatus(
                args.osdpl, args.namespace
            )
            child_view = resource_view.ChildObjectView(osdpl.mspec)
            loop = asyncio.get_event_loop()
            while True:
                if osdplst.get_osdpl_status() == osdplstatus.APPLYING:
                    break
                time.sleep(10)
            while True:
                if osdplst.get_osdpl_status() == osdplstatus.APPLIED:
                    LOG.info(f"Waiting openstack services are healty.")
                    if loop.run_until_complete(
                        health.wait_services_healthy(
                            osdpl.mspec, osdplst, child_view
                        )
                    ):
                        break
                time.sleep(10)
