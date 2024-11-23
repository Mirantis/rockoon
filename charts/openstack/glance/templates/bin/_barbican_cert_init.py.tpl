#!/usr/bin/env python

import base64
import datetime
import sys
import hashlib
import logging
import os
import openstack
import tempfile
import uuid
import yaml
import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pykube
from retry import retry
from retry.api import retry_call

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)

SECRET_NAME = os.getenv("SECRET_NAME", "glance-barbican-cert")
SECRET_NAMESPACE = os.getenv("SECRET_NAMESPACE", "openstack")

CERT_COMMON_NAME = os.getenv("COMMON_NAME", "OpenStackHelm")
CERT_ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME", "OpenStackHelm")
CERT_ORGANIZATIONAL_UNIT_NAME = os.getenv(
    "ORGANIZATIONAL_UNIT_NAME", "OpenStack Helm Internal"
)
CERT_NOT_VALID_AFTER = os.getenv("NOT_VALID_AFTER", "2086-10-08")
CERT_KEY_SIZE = int(os.getenv("CA_KEY_SIZE", "2048"))


def initCert(
    common_name, organization_name, organization_unit_name, not_valid_after, key_size
):
    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit_name
                ),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
    )
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.strptime(not_valid_after, "%Y-%m-%d")
    )
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )
    return (private_key, public_key)


@retry(pykube.exceptions.KubernetesError, delay=1, tries=7, backoff=2, logger=LOG)
def ensure_barbican_cert():
    secret_name = SECRET_NAME
    secret_namespace = SECRET_NAMESPACE
    secret = (
        pykube.Secret.objects(kube)
        .filter(namespace=secret_namespace)
        .get_or_none(name=secret_name)
    )
    LOG.info(f"Looking for kubernetes secret {secret_name}")
    if secret is None:
        LOG.info(f"The secrets {secret_name} does not exists.")
        private_key, public_key = initCert(
            CERT_COMMON_NAME,
            CERT_ORGANIZATION_NAME,
            CERT_ORGANIZATIONAL_UNIT_NAME,
            CERT_NOT_VALID_AFTER,
            CERT_KEY_SIZE,
        )

        LOG.info(f"Storing barbican secret {secret_name}")
        barbican_secret = ost.key_manager.create_secret(
            name=secret_name,
            secret_type="certificate",
            algorithm="RSA",
            payload=base64.b64encode(public_key).decode(),
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64",
        )
        barbican_secret_uuid = barbican_secret.secret_id
        LOG.info(f"The barbican secret {barbican_secret_uuid} created successfully.")

        LOG.info(f"Creating barbican kubernetes secret {secret_name}.")
        secret_data = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret_name,
                "namespace": secret_namespace,
            },
            "data": {
                "private_key.pem": base64.b64encode(private_key).decode(),
                "public_key.pem": base64.b64encode(public_key).decode(),
                "barbican_secret_uuid": base64.b64encode(
                    barbican_secret_uuid.encode()
                ).decode(),
            },
        }

        pykube.Secret(kube, secret_data).create()
        LOG.info(f"Created kubernetes secret {secret_name} successfully.")
    LOG.info(f"Finished handling {secret_name}")


ost = openstack.connect()
kube = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)
ensure_barbican_cert()
