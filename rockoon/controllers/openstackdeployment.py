import asyncio
import os

import kopf

from rockoon import cache
from rockoon import constants
from rockoon import kube
from rockoon import layers
from rockoon import maintenance
from rockoon import secrets
from rockoon import services
from rockoon import settings  # noqa
from rockoon import version
from rockoon import utils
from rockoon import osdplstatus
from rockoon import resource_view


LOG = utils.get_logger(__name__)


def is_openstack_version_changed(diff):
    for diff_item in diff:
        if diff_item.field == ("spec", "openstack_version"):
            return True


def get_os_services_for_upgrade(enabled_services):
    return [
        service
        for service in constants.OPENSTACK_SERVICES_UPGRADE_ORDER
        if service in enabled_services
    ]


def check_handling_allowed(old, new, event):
    LOG.info(f"Checking whether handling is allowed")

    new_values = (
        new.get("spec", {})
        .get("services", {})
        .get("database", {})
        .get("mariadb", {})
        .get("values", {})
    )
    new_enabled = new_values.get("manifests", {}).get(
        "job_mariadb_phy_restore", False
    )

    if new_enabled:
        if event == "create":
            raise kopf.PermanentError(
                f"Mariadb restore cannot be enabled during Openstack deployment create"
            )
        elif event == "resume":
            raise kopf.PermanentError(
                f"Resume is blocked due to Mariadb restore job enabled"
            )
        else:
            old_values = (
                old.get("spec", {})
                .get("services", {})
                .get("database", {})
                .get("mariadb", {})
                .get("values", {})
            )
            old_enabled = old_values.get("manifests", {}).get(
                "job_mariadb_phy_restore", False
            )
            if old_enabled:
                raise kopf.PermanentError(
                    f"Mariadb restore job should be disabled before doing other changes, handling is not allowed"
                )
    LOG.info("Handling is allowed")


async def run_task(task_def):
    """Run OpenStack controller tasks

    Runs tasks passed as `task_def` with implementing the following logic:

    * In case of permanent error retry all the tasks that finished with
      TemporaryError and fail permanently.

    * In case of unknown error retry the task as we and kopf treat error as
      environment issue which is self-recoverable. Do retries by our own
      to avoid dead locks between dependent tasks.

    :param task_def: Dictionary with the task definitions.
    :raises: kopf.PermanentError when permanent error occur.
    """

    permanent_exception = None

    while task_def:
        # NOTE(e0ne): we can switch to asyncio.as_completed to run tasks
        # faster if needed.
        done, _ = await asyncio.wait(task_def.keys())
        for task in done:
            coro, event, body, meta, spec, logger, kwargs = task_def.pop(task)
            if task.exception():
                if isinstance(task.exception(), kopf.PermanentError):
                    LOG.error(f"Failed to apply {coro} permanently.")
                    LOG.error(task.print_stack())
                    permanent_exception = kopf.PermanentError(
                        "Permanent error occured."
                    )
                else:
                    LOG.warning(
                        f"Got retriable exception when applying {coro}, retrying..."
                    )
                    LOG.warning(task.print_stack())
                    task_def[
                        asyncio.create_task(
                            coro(
                                event=event,
                                body=body,
                                meta=meta,
                                spec=spec,
                                logger=logger,
                                **kwargs,
                            )
                        )
                    ] = (coro, event, body, meta, spec, logger, kwargs)

        # Let's wait for 10 second before retry to not introduce a lot of
        # task scheduling in case of some depended task is slow.
        LOG.info("Sleeping ...")
        await asyncio.sleep(10)

    if permanent_exception:
        raise permanent_exception


def cleanup_helm_cache():
    LOG.info(f"Cleaning helm cache in {settings.HELM_REPOSITORY_CACHE}")
    for root, dirs, files in os.walk(settings.HELM_REPOSITORY_CACHE):
        for file in files:
            os.remove(os.path.join(root, file))


async def _rotate_creds(
    group_name,
    rotation_id,
    enabled_services,
    mspec,
    logger,
    osdplst,
    reason,
    body,
    meta,
    spec,
    child_view,
    **kwargs,
):
    if group_name == "admin":
        secrets.OpenStackAdminSecret(osdplst.namespace).rotate(rotation_id)
        mariadb_instance = services.registry["database"](
            mspec, logger, osdplst, child_view
        )
        task_def = {}
        task_def[
            asyncio.create_task(
                mariadb_instance.apply(
                    event=reason,
                    body=body,
                    meta=meta,
                    spec=spec,
                    logger=logger,
                    **kwargs,
                )
            )
        ] = (mariadb_instance.apply, reason, body, meta, spec, logger, kwargs)
        await run_task(task_def)
        await asyncio.sleep(60)
        await mariadb_instance.wait_service_healthy()
    elif group_name == "service":
        for service in enabled_services:
            service_instance = services.registry[service](
                mspec, logger, osdplst, child_view
            )
            service_secret = service_instance.service_secret
            if service_secret:
                LOG.info(f"Starting rotation service users for {service}")
                service_secret.rotate(rotation_id)


async def rotate_credentials(
    enabled_services,
    mspec,
    logger,
    osdplst,
    reason,
    body,
    meta,
    spec,
    child_view,
    **kwargs,
):
    new_credentials = utils.get_in(
        kwargs.get("new", {}), ["status", "credentials"], {}
    )
    for group_name in ["admin", "service"]:
        new_rotation_id = utils.get_in(
            new_credentials, [group_name, "rotation_id"], 0
        )

        if new_rotation_id:
            old_credentials = utils.get_in(
                kwargs["old"], ["status", "credentials"], {}
            )
            old_rotation_id = utils.get_in(
                old_credentials, [group_name, "rotation_id"], 0
            )
            if new_rotation_id != old_rotation_id:
                LOG.info(f"Starting rotation for {group_name}")
                await _rotate_creds(
                    group_name,
                    new_rotation_id,
                    enabled_services,
                    mspec,
                    logger,
                    osdplst,
                    reason,
                    body,
                    meta,
                    spec,
                    child_view,
                    **kwargs,
                )
                LOG.info(f"Finished rotation for {group_name}")


# on.field to force storing that field to be reacting on its changes
@kopf.on.field(*kube.OpenStackDeployment.kopf_on_args, field="status.watched")
@kopf.on.field(
    *kube.OpenStackDeployment.kopf_on_args, field="status.credentials"
)
@kopf.on.resume(*kube.OpenStackDeployment.kopf_on_args)
@kopf.on.update(*kube.OpenStackDeployment.kopf_on_args)
@kopf.on.create(*kube.OpenStackDeployment.kopf_on_args)
def handle(body, meta, spec, logger, reason, **kwargs):
    asyncio.run(_handle(body, meta, spec, logger, reason, **kwargs))


async def _handle(body, meta, spec, logger, reason, **kwargs):
    # TODO(pas-ha) remove all this kwargs[*] nonsense, accept explicit args,
    # pass further only those that are really needed
    # actual **kwargs form is for forward-compat with kopf itself
    namespace = meta["namespace"]
    name = meta["name"]
    LOG.info(f"Got osdpl event {reason}")
    utils.log_changes(kwargs.get("old", {}), kwargs.get("new", {}))

    if spec.get("draft"):
        LOG.info("OpenStack deployment is in draft mode, skipping handling...")
        return {"lastStatus": f"{reason} drafted"}

    # TODO(vsaienko): remove legacy status
    kwargs["patch"].setdefault("status", {})
    kwargs["patch"]["status"]["version"] = version.release_string
    osdplst = osdplstatus.OpenStackDeploymentStatus(name, namespace)
    osdplst.present(osdpl_obj=body)
    osdpl = kube.get_osdpl()
    mspec = osdpl.mspec

    osdplst.set_osdpl_status(
        osdplstatus.APPLYING, mspec, kwargs["diff"], reason
    )

    # Always create clusterworkloadlock, but set to inactive when we are not interested
    cwl = maintenance.ClusterWorkloadLock.get_by_osdpl(name)
    cwl.present()

    check_handling_allowed(kwargs["old"], kwargs["new"], reason)

    secrets.OpenStackAdminSecret(namespace).ensure()
    child_view = resource_view.ChildObjectView(mspec)

    kwargs["patch"]["status"]["fingerprint"] = layers.spec_hash(mspec)

    cache.ensure(body, mspec)

    update, delete = layers.services(mspec, logger, **kwargs)

    await rotate_credentials(
        update,
        mspec,
        logger,
        osdplst,
        reason,
        body,
        meta,
        spec,
        child_view,
        **kwargs,
    )

    if is_openstack_version_changed(kwargs["diff"]):
        # Suspend descheduler cronjob during the upgrade services
        service_instance_descheduler = services.registry["descheduler"](
            mspec, logger, osdplst, child_view
        )
        child_obj_descheduler = service_instance_descheduler.get_child_object(
            "CronJob", "descheduler"
        )
        await child_obj_descheduler.suspend(wait_completion=True)

        services_to_upgrade = get_os_services_for_upgrade(update)
        LOG.info(
            f"Starting upgrade for the following services: {services_to_upgrade}"
        )
        for service in set(list(services_to_upgrade) + list(update)):
            osdplst.set_service_state(service, osdplstatus.WAITING)
        for service in services_to_upgrade:
            task_def = {}
            service_instance = services.registry[service](
                mspec, logger, osdplst, child_view
            )
            task_def[
                asyncio.create_task(
                    service_instance.upgrade(
                        event=reason,
                        body=body,
                        meta=meta,
                        spec=spec,
                        logger=logger,
                        **kwargs,
                    )
                )
            ] = (
                service_instance.upgrade,
                reason,
                body,
                meta,
                spec,
                logger,
                kwargs,
            )
            await run_task(task_def)

    # NOTE(vsaienko): explicitly call apply() here to make sure that newly deployed environment
    # and environment after upgrade/update are identical.
    task_def = {}
    for service in update:
        service_instance = services.registry[service](
            mspec, logger, osdplst, child_view
        )
        task_def[
            asyncio.create_task(
                service_instance.apply(
                    event=reason,
                    body=body,
                    meta=meta,
                    spec=spec,
                    logger=logger,
                    **kwargs,
                )
            )
        ] = (service_instance.apply, reason, body, meta, spec, logger, kwargs)

    if delete:
        LOG.info(f"deleting children {' '.join(delete)}")
    for service in delete:
        service_instance = services.registry[service](
            mspec, logger, osdplst, child_view
        )
        task_def[
            asyncio.create_task(
                service_instance.delete(
                    body=body, meta=meta, spec=spec, logger=logger, **kwargs
                )
            )
        ] = (service_instance.delete, reason, body, meta, spec, logger, kwargs)

    await run_task(task_def)

    # TODO(vsaienko): remove when release boundary passed. Cleanup status from osdpl
    # object.
    kwargs["patch"]["status"]["health"] = None
    kwargs["patch"]["status"]["children"] = None
    kwargs["patch"]["status"]["deployed"] = None
    osdplst.set_osdpl_status(
        osdplstatus.APPLIED, mspec, kwargs["diff"], reason
    )

    cleanup_helm_cache()

    return {"lastStatus": f"{reason}d"}


@kopf.on.delete(*kube.OpenStackDeployment.kopf_on_args)
def delete(name, meta, body, spec, logger, reason, **kwargs):
    asyncio.run(_delete(name, meta, body, spec, logger, reason, **kwargs))


async def _delete(name, meta, body, spec, logger, reason, **kwargs):
    # TODO(pas-ha) wait for children to be deleted
    # TODO(pas-ha) remove secrets and so on?
    LOG.info(f"Deleting {name}")
    namespace = meta["namespace"]
    osdpl = kube.get_osdpl()
    mspec = osdpl.mspec
    child_view = resource_view.ChildObjectView(mspec)
    osdplst = osdplstatus.OpenStackDeploymentStatus(name, namespace)
    delete_services = layers.services(mspec, logger, **kwargs)[0]
    for service in delete_services:
        LOG.info(f"Deleting {service} service")
        task_def = {}
        service_instance = services.registry[service](
            mspec, logger, osdplst, child_view
        )
        task_def[
            asyncio.create_task(
                service_instance.delete(
                    body=body, meta=meta, spec=spec, logger=logger, **kwargs
                )
            )
        ] = (service_instance.delete, reason, body, meta, spec, logger, kwargs)
        await run_task(task_def)
    # TODO(dbiletskiy) delete osdpl status
    maintenance.ClusterWorkloadLock.get_by_osdpl(name).absent()
