import copy
import pytest
import kopf
import rockoon.controllers.openstackdeployment as osdpl

OBJ = {
    "spec": {
        "openstack_version": "ussuri",
        "preset": "compute",
        "size": "tiny",
        "features": {
            "services": ["key-manager", "object-storage"],
            "neutron": {"floating_network": {"physnet": "physnet1"}},
        },
    }
}

DATABASE_SETTINGS = {
    "database": {
        "mariadb": {
            "values": {
                "conf": {
                    "phy_restore": {
                        "backup_name": "2021-07-20_15-12-49/2021-07-20_15-18-42"
                    }
                },
                "manifests": {"job_mariadb_phy_restore": True},
            }
        }
    }
}


def test_allowed_handling_on_create():
    event = "create"
    old = None
    new = copy.deepcopy(OBJ)
    osdpl.check_handling_allowed(old, new, event)


def test_denied_mariadb_phy_restore_handling_on_create():
    event = "create"
    old = None
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    with pytest.raises(
        kopf.PermanentError,
        match="Mariadb restore cannot be enabled during Openstack deployment create",
    ):
        osdpl.check_handling_allowed(old, new, event)


def test_enable_mariadb_phy_restore_allowed_handling_on_update():
    event = "update"
    old = copy.deepcopy(OBJ)
    new = copy.deepcopy(old)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    osdpl.check_handling_allowed(old, new, event)


def test_mariadb_phy_restore_denied_handling_on_update():
    event = "update"
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    old = copy.deepcopy(new)
    old["spec"]["features"]["foo"] = "bar"
    with pytest.raises(
        kopf.PermanentError,
        match=f"Mariadb restore job should be disabled before doing other changes, handling is not allowed",
    ):
        osdpl.check_handling_allowed(old, new, event)


def test_disable_mariadb_phy_restore_allowed_handling_on_update():
    event = "update"
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    old = copy.deepcopy(new)
    new["spec"]["services"]["database"]["mariadb"]["values"]["manifests"][
        "job_mariadb_phy_restore"
    ] = False
    osdpl.check_handling_allowed(old, new, event)


def test_config_mariadb_phy_restore_denied_handling_on_update():
    event = "update"
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    old = copy.deepcopy(new)
    new["spec"]["services"]["database"]["mariadb"]["values"]["conf"][
        "phy_restore"
    ]["backup_name"] = "test_back"
    with pytest.raises(
        kopf.PermanentError,
        match=f"Mariadb restore job should be disabled before doing other changes, handling is not allowed",
    ):
        osdpl.check_handling_allowed(old, new, event)


def test_mariadb_phy_restore_denied_handling_on_resume():
    event = "resume"
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    old = copy.deepcopy(new)
    with pytest.raises(
        kopf.PermanentError,
        match=f"Resume is blocked due to Mariadb restore job enabled",
    ):
        osdpl.check_handling_allowed(old, new, event)


def test_allowed_handling_on_resume():
    event = "resume"
    new = copy.deepcopy(OBJ)
    new["spec"]["services"] = copy.deepcopy(DATABASE_SETTINGS)
    new["spec"]["services"]["database"]["mariadb"]["values"]["manifests"][
        "job_mariadb_phy_restore"
    ] = False
    old = copy.deepcopy(new)
    osdpl.check_handling_allowed(old, new, event)
