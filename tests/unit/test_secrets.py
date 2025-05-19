import base64
import copy
import json
import jsonschema
from unittest import mock

import pykube
import pytest

from rockoon import secrets


def test_openstack_service_secret_name():
    secret = secrets.OpenStackServiceSecret("ns", "service")
    assert secret.secret_base_name == "generated-service-passwords"


def test_generate_name():
    assert len(secrets.generate_name("admin", 16)) == 16
    assert len(secrets.generate_name("123456789112345678", 16)) == 16


@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_openstack_admin_secret_create(mock_name, mock_password):
    username = "adminxav1"
    password = "password"
    mock_name.return_value = username
    mock_password.return_value = password
    secret = secrets.OpenStackAdminSecret("ns")
    creds = secret.create()
    assert creds.database.username == "root"
    assert creds.database.password == password
    assert creds.identity.username == username
    assert creds.identity.password == password
    assert creds.messaging.username == "rabbitmq"
    assert creds.messaging.password == password

    assert mock_name.call_count == 1
    assert mock_password.call_count == 3


@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_openstack_admin_secret_new_password(mock_name, mock_password):
    username = "adminxav1"
    password = "password"
    mock_name.return_value = username
    mock_password.return_value = password
    secret = secrets.OpenStackAdminSecret("ns")
    creds = secret.secret_class.to_json(secret.create())

    new_password = "password1"
    mock_password.return_value = new_password
    new = secret._fill_new_fields(creds, {"identity": ["password"]})

    assert new.database.username == "root"
    assert new.database.password == password
    assert new.identity.username == username
    assert new.identity.password == new_password
    assert new.messaging.username == "rabbitmq"
    assert new.messaging.password == password


@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_openstack_admin_secret_new_identity(mock_name, mock_password):
    username = "adminxav1"
    password = "password"
    mock_name.return_value = username
    mock_password.return_value = password
    secret = secrets.OpenStackAdminSecret("ns")
    creds = secret.secret_class.to_json(secret.create())

    new_username = "admin1abc"
    new_password = "password1"
    mock_name.return_value = new_username
    mock_password.return_value = new_password
    new = secret._fill_new_fields(creds, {"identity": []})

    assert new.database.username == "root"
    assert new.database.password == password
    assert new.identity.username == new_username
    assert new.identity.password == new_password
    assert new.messaging.username == "rabbitmq"
    assert new.messaging.password == password


@mock.patch("rockoon.secrets.OpenStackServiceSecret.create")
def test_openstack_service_secret_fill_fields(mock_secret_create):
    secret = secrets.OpenStackServiceSecret("openstack", "myservice")
    old = {
        "notifications": {
            "user": {"username": "olduser", "password": "oldpw"}
        },
        "messaging": {"user": {"username": "olduser", "password": "oldpw"}},
        "database": {"user": {"username": "olduser", "password": "oldpw"}},
        "memcached": "oldpw",
        "identity": {"myuser": {"username": "olduser", "password": "oldpw"}},
    }
    new = {
        "notifications": {
            "user": {"username": "newuser", "password": "newpw"}
        },
        "messaging": {"user": {"username": "newuser", "password": "newpw"}},
        "database": {"user": {"username": "newuser", "password": "newpw"}},
        "memcached": "newpw",
        "identity": {"myuser": {"username": "newuser", "password": "newpw"}},
    }

    mock_secret_create.return_value = secrets.OpenStackCredentials(**new)
    old_copy = copy.deepcopy(old)
    res = secret._fill_new_fields(
        old,
        {
            "notifications": [],
            "database": {"user": ["password"]},
            "messaging": {"user": []},
            "identity": {"myuser": ["password"]},
        },
    )
    res = secrets.OpenStackCredentials.to_json(res)
    # Make sure original object is not changed
    assert old_copy == old

    assert res["notifications"] == new["notifications"]
    assert res["messaging"] == {
        "user": {"username": "newuser", "password": "newpw"}
    }
    assert res["memcached"] == old["memcached"]
    assert res["database"] == {
        "user": {"username": "olduser", "password": "newpw"}
    }
    assert res["identity"] == {
        "myuser": {"username": "olduser", "password": "newpw"}
    }


@mock.patch("rockoon.secrets.OpenStackServiceSecret.create")
def test_openstack_service_secret_fill_fields_missing(mock_secret_create):
    secret = secrets.OpenStackServiceSecret("openstack", "myservice")
    old = {
        "notifications": {
            "user": {"username": "olduser", "password": "oldpw"}
        },
        "messaging": {"user": {"username": "olduser", "password": "oldpw"}},
        "database": {"user1": {"username": "olduser", "password": "oldpw"}},
        "memcached": "oldpw",
    }
    new = {
        "notifications": {
            "user": {"username": "newuser", "password": "newpw"}
        },
        "messaging": {"user": {"username": "newuser", "password": "newpw"}},
        "database": {
            "user1": {"username": "newuser", "password": "newpw"},
            "user2": {"username": "newuser", "password": "newpw"},
        },
        "memcached": "newpw",
        "identity": {"myuser": {"username": "newuser", "password": "newpw"}},
    }

    mock_secret_create.return_value = secrets.OpenStackCredentials(**new)
    res = secret._fill_new_fields(
        old,
        {
            "database": {"user2": []},
            "identity": [],
        },
    )
    res = secrets.OpenStackCredentials.to_json(res)
    assert res["database"] == {
        "user1": {"username": "olduser", "password": "oldpw"},
        "user2": {"username": "newuser", "password": "newpw"},
    }
    assert res["identity"] == {
        "myuser": {"username": "newuser", "password": "newpw"}
    }


@mock.patch("rockoon.kube.save_secret_data")
def test_stacklight_config_secret_save(mock_save_secret):
    expected_config = {"exporters": {"cloudprober": {"enabled": False}}}
    secret = secrets.StackLightConfigSecret()
    secret.save({"conf.json": expected_config})
    expected = {
        "conf.json": base64.b64encode(
            json.dumps(expected_config).encode()
        ).decode()
    }

    assert mock_save_secret.call_args[0][2] == expected


@mock.patch("rockoon.kube.save_secret_data")
def test_stacklight_config_secret_save_fail(mock_save_secret):
    incorrect_config = {"exporters": {"cloudprober": {"incorrect": "format"}}}
    secret = secrets.StackLightConfigSecret()
    with pytest.raises(jsonschema.exceptions.ValidationError):
        secret.save({"conf.json": incorrect_config})


@mock.patch("rockoon.secrets.get_secret_data")
def test_bgpvpn_secret_get_peer_ips(mock_get_secret):
    expected = ["10.15.0.1", "10.15.0.2", "10.15.0.3"]
    encoded = {}
    for index, ip in enumerate(expected):
        encoded[f"node-{index}"] = base64.b64encode(
            json.dumps({"bgp": {"source_ip": ip}}).encode()
        ).decode()
    mock_get_secret.return_value = encoded

    secret = secrets.BGPVPNSecret()
    result = secret.get_peer_ips()

    assert set(expected) == set(result)


@mock.patch("rockoon.secrets.OpenStackServiceSecret.create")
def test_openstack_service_secret_protect_username(mock_secret_create):
    secret = secrets.OpenStackServiceSecret("openstack", "myservice")
    old = {
        "notifications": {
            "user": {"username": "olduser", "password": "oldpw"}
        },
        "messaging": {"user": {"username": "olduser", "password": "oldpw"}},
        "database": {"user": {"username": "olduser", "password": "oldpw"}},
        "memcached": "oldhash",
        "identity": {
            "user1": {"username": "olduser1", "password": "oldpw1"},
            "user2": {"username": "olduser2", "password": "oldpw2"},
        },
    }
    new = {
        "notifications": {
            "user": {"username": "newuser", "password": "newpw"}
        },
        "messaging": {"user": {"username": "newuser", "password": "newpw"}},
        "database": {"user": {"username": "newuser", "password": "newpw"}},
        "memcached": "newhash",
        "identity": {
            "user1": {"username": "newuser1", "password": "newpw1"},
            "user2": {"username": "newuser2", "password": "newpw2"},
        },
    }

    mock_secret_create.return_value = secrets.OpenStackCredentials(**new)
    res = secret._fill(
        old,
        new,
        {
            "identity": {"user1": ["username"]},
            "messaging": {"user": []},
            "memcached": [],
        },
    )
    assert res["identity"] == {
        "user1": {"username": "olduser1", "password": "newpw1"},
        "user2": {"username": "newuser2", "password": "newpw2"},
    }
    assert res["messaging"] == {
        "user": {"username": "olduser", "password": "oldpw"}
    }
    assert res["memcached"] == "oldhash"


@mock.patch("rockoon.secrets.get_secret_data")
@mock.patch("rockoon.secrets.generate_password")
def test_keycloak_secret_serialization(mock_password, mock_data):
    passphrase = "passphrase"
    mock_password.return_value = passphrase

    secret_data = {
        "passphrase": base64.b64encode(json.dumps(passphrase).encode())
    }

    mock_data.side_effect = [pykube.exceptions.ObjectDoesNotExist, secret_data]

    secret = secrets.KeycloakSecret("ns")

    secret.ensure()
    from_secret = secret.get().passphrase

    assert from_secret == passphrase


@mock.patch("rockoon.secrets.get_secret_data")
@pytest.mark.parametrize(
    "override_setting",
    [{"name": "OSCTL_PROXY_DATA", "value": {"secretName": "cc-proxy"}}],
    indirect=["override_setting"],
)
def test_get_proxy_vars_from_secret(mock_data, override_setting):
    mock_data.return_value = {
        "HTTP_PROXY": "aHR0cDovL3NxdWlkLm9wZW5zdGFjay5zdmMuY2x1c3Rlci5sb2NhbDo4MA==",
        "HTTPS_PROXY": "aHR0cDovL3NxdWlkLm9wZW5zdGFjay5zdmMuY2x1c3Rlci5sb2NhbDo4MA==",
        # test.domain.local
        "NO_PROXY": "dGVzdC5kb21haW4ubG9jYWw=",
        "PROXY_CA_CERTIFICATE": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCnRlc3RfY2EKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
    }

    secret = secrets.ProxySecret()

    proxy_vars = secret.get_proxy_vars(
        no_proxy=["svc.cluster.local", "it.just.works"]
    )
    proxy_certs = secret.get_proxy_certs()

    expected_proxy = "http://squid.openstack.svc.cluster.local:80"
    expected_no_proxy = "it.just.works,svc.cluster.local,test.domain.local"

    expected_vars = {
        "HTTP_PROXY": expected_proxy,
        "HTTPS_PROXY": expected_proxy,
        "NO_PROXY": expected_no_proxy,
        "http_proxy": expected_proxy,
        "https_proxy": expected_proxy,
        "no_proxy": expected_no_proxy,
    }

    expected_ca_cert = (
        "-----BEGIN CERTIFICATE-----\n"
        "test_ca\n"
        "-----END CERTIFICATE-----\n"
    )

    assert expected_vars == proxy_vars
    assert expected_ca_cert == proxy_certs


@mock.patch("rockoon.secrets.Secret.save")
@mock.patch("rockoon.secrets.get_secret_data")
@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_galera_secret(mock_name, mock_password, mock_secret_data, mock_save):
    creds_b64 = base64.b64encode(
        json.dumps({"username": "username", "password": "password"}).encode()
    )

    mock_name.return_value = "username"
    mock_password.return_value = "password"

    mock_secret_data.return_value = {
        "sst": creds_b64,
        "exporter": creds_b64,
        "audit": creds_b64,
        "openssl_kek": "b3BlbnNzbGtlaw==",
    }
    galera_secret = secrets.GaleraSecret("ns")
    galera_secret.ensure()

    system_creds = secrets.OSSytemCreds(
        username="username", password="password"
    )
    expected = secrets.GaleraCredentials(
        sst=system_creds,
        exporter=system_creds,
        audit=system_creds,
        backup=system_creds,
        openssl_kek="opensslkek",
    )

    mock_name.assert_called_with(prefix="backup", length=8)
    mock_password.assert_called_with(length=64)
    mock_secret_data.assert_called_with("ns", galera_secret.secret_name)

    assert mock_save.call_args[0][0] == expected


@mock.patch("rockoon.secrets.get_secret_data")
@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_galera_secret_new_password(
    mock_name, mock_password, mock_secret_data
):
    old_name = "username"
    old_password = "password"

    creds_b64 = base64.b64encode(
        json.dumps({"username": old_name, "password": old_password}).encode()
    )

    mock_name.return_value = "username"
    mock_password.return_value = "password"
    mock_secret_data.return_value = {
        "sst": creds_b64,
        "exporter": creds_b64,
        "audit": creds_b64,
        "backup": creds_b64,
        "openssl_kek": "b3BlbnNzbGtlaw==",
    }
    galera_secret = secrets.GaleraSecret("ns")
    actual = galera_secret.get()

    new_name = "username1"
    new_password = "password1"
    mock_name.return_value = new_name
    mock_password.return_value = new_password
    new = galera_secret._fill_new_fields(
        galera_secret.secret_class.to_json(actual),
        {"sst": ["password"], "exporter": ["password"]},
    )

    old_creds = secrets.OSSytemCreds(username=old_name, password=old_password)
    new_creds = secrets.OSSytemCreds(username=old_name, password=new_password)
    expected = secrets.GaleraCredentials(
        sst=new_creds,
        exporter=new_creds,
        audit=old_creds,
        backup=old_creds,
        openssl_kek="opensslkek",
    )

    mock_secret_data.assert_called_once_with("ns", galera_secret.secret_name)

    assert new == expected


@mock.patch("rockoon.secrets.get_secret_data")
@mock.patch("rockoon.secrets.generate_password")
@mock.patch("rockoon.secrets.generate_name")
def test_galera_secret_new_credentials(
    mock_name, mock_password, mock_secret_data
):
    old_name = "username"
    old_password = "password"

    creds_b64 = base64.b64encode(
        json.dumps({"username": old_name, "password": old_password}).encode()
    )

    mock_name.return_value = "username"
    mock_password.return_value = "password"
    mock_secret_data.return_value = {
        "sst": creds_b64,
        "exporter": creds_b64,
        "audit": creds_b64,
        "backup": creds_b64,
        "openssl_kek": "b3BlbnNzbGtlaw==",
    }
    galera_secret = secrets.GaleraSecret("ns")
    actual = galera_secret.secret_class.to_json(galera_secret.get())

    new_name = "username1"
    new_password = "password1"
    mock_name.return_value = new_name
    mock_password.return_value = new_password
    new = galera_secret._fill_new_fields(actual, {"sst": [], "exporter": []})

    old_creds = secrets.OSSytemCreds(username=old_name, password=old_password)
    new_creds = secrets.OSSytemCreds(username=new_name, password=new_password)
    expected = secrets.GaleraCredentials(
        sst=new_creds,
        exporter=new_creds,
        audit=old_creds,
        backup=old_creds,
        openssl_kek="opensslkek",
    )

    mock_secret_data.assert_called_once_with("ns", galera_secret.secret_name)

    assert new == expected
