#!/usr/bin/env python

{{/*
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
Distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
Limitations under the License.
*/}}

import base64
import os
import openstack
import sys
import hashlib
import logging
import tempfile
import yaml
import requests


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding
import pykube
from retry import retry
from retry.api import retry_call
from urllib.parse import urlsplit, urljoin

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)

STRUCTURED_IMAGES = '{{ .Values.bootstrap.structured.images | toJson }}'
STRUCTURED_IMAGES = yaml.safe_load(STRUCTURED_IMAGES)

SECRET_NAME = os.getenv("SECRET_NAME", "{{ .Values.conf.barbican_cert.secret_name }}")
SECRET_NAMESPACE = os.getenv("SECRET_NAMESPACE", "{{ .Release.Namespace }}")
NODE_IP = os.getenv("NODE_IP", "127.0.0.1")

HASH_METHODS = {
    "SHA-224": hashes.SHA224(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}

def substitute_local_proxy_hostname(url, hostname):
    """Point artifact to use nodeIP instead of 127.0.0.1"""
    parsed = urlsplit(url)
    if not parsed.hostname == "127.0.0.1":
        return url
    new_netloc = hostname
    auth = parsed.username
    new_netloc = hostname
    if auth:
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        new_netloc = f"{auth}@{new_netloc}"
    if parsed.port:
        new_netloc = f"{new_netloc}:{parsed.port}"
    return parsed._replace(netloc=new_netloc).geturl()


@retry(requests.exceptions.RequestException, delay=1, tries=7, backoff=2, logger=LOG)
def download_file(url, dst_file, checksum=None):
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    actual_image_checksum = hashlib.md5()

    with open(dst_file, "wb+") as f:
        for chunk in r.iter_content(
            chunk_size=65536 * actual_image_checksum.block_size
        ):
            actual_image_checksum.update(chunk)
            f.write(chunk)
    if checksum and actual_image_checksum.hexdigest() != checksum:
        LOG.error("Got broken/incorrect amphora image")
        sys.exit(1)
    return {"checksum": actual_image_checksum.hexdigest()}


@retry(requests.exceptions.RequestException, delay=1, tries=7, backoff=2, logger=LOG)
def get_secret_data(secret_name, secret_namespace):
    secret = (
        pykube.Secret.objects(kube)
        .filter(namespace=secret_namespace)
        .get_or_none(name=secret_name)
    )
    if secret is None:
        requests.exceptions.RequestException(f"The secret {secret_name} does not exist...")
    return secret.obj["data"]


def read_chunks(file, size):
    """Yield pieces of data from a file-like object until EOF."""
    while True:
        chunk = file.read(size)
        if not chunk:
            break
        yield chunk


def sign_image(dst_file, hash_method, private_key):
    chosen_hash = HASH_METHODS[hash_method]

    private_key = serialization.load_pem_private_key(
        private_key, password=None, backend=default_backend()
    )
    hasher = hashes.Hash(chosen_hash, backend=default_backend())

    with open(dst_file, "rb") as f:
        for chunk in read_chunks(f, size=65536 * chosen_hash.block_size):
            hasher.update(chunk)
    digest = hasher.finalize()
    signature = private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(chosen_hash),
    )
    return signature


kube = pykube.HTTPClient(config=pykube.KubeConfig.from_env(), timeout=30)
ost = openstack.connect()

for image_name, image in STRUCTURED_IMAGES.items():
    image_name = image.pop("name", image_name)
    LOG.info(f"Handling image: {image_name}")
    ost_image = ost.image.find_image(image_name)
    checksum = image.pop("checksum", None)
    url = image["source_url"]
    if "image_file" in image:
        url = urljoin(url, image["image_file"])

    url = substitute_local_proxy_hostname(url, NODE_IP)

    if ost_image:
        LOG.debug("Image exists. Checking checksumm.")
        if ost_image.checksum == checksum:
            LOG.debug("The checksumm match")
            continue

    signature = image.get("signature", {"enabled": False})

    with tempfile.NamedTemporaryFile() as tmp:
        dst_file = tmp.name
        LOG.info(f"Downloading image {url}...")
        res = download_file(url, dst_file, checksum)
        LOG.info("Finished image download...")

        visibility = image.get(
            "visibility", "public" if image.get("private", False) else "private"
        )
        attrs = {
            "name": image_name,
            "filename": dst_file,
            "disk_format": image.get("disk_format", image.get("image_type", "qcow2")),
            "container_format": image["container_format"],
            "visibility": image.get("visibility", "public"),
            "tags": image.get("tags", []),
        }
        if signature["enabled"]:
            LOG.info("Signing image.")
            secret_data = get_secret_data(SECRET_NAME, SECRET_NAMESPACE)
            hash_method = signature["hash_method"]
            private_key = base64.b64decode(secret_data["private_key.pem"])
            barbican_secret_uuid = base64.b64decode(
                secret_data["barbican_secret_uuid"]
            ).decode()
            sign_data = sign_image(dst_file, hash_method, private_key)
            base64_sign = base64.b64encode(sign_data).decode()
            sign_attr = {
                "img_signature": base64_sign,
                "img_signature_hash_method": signature["hash_method"],
                "img_signature_key_type": "RSA-PSS",
                "img_signature_certificate_uuid": barbican_secret_uuid,
            }
            attrs.update(sign_attr)

        LOG.info(f"Creating image {attrs}")
        properties = image.pop("properties", {})
        attrs.update(properties)
        if not ost_image:
            LOG.info("Creating image")
            ost.image.create_image(**attrs)
        else:
            if res["checksum"] != ost_image.checksum:
                LOG.info("The checksum doesn't match. Removing image...")
                retry_call(
                    ost.image.delete_image,
                    fargs=[ost_image.id],
                    fkwargs={"ignore_missing": False},
                    exceptions=requests.exceptions.RequestException,
                    tries=7,
                    delay=1,
                    jitter=2,
                    logger=LOG,
                )
                LOG.info("Creating image")
                retry_call(
                    ost.image.create_image,
                    fkwargs=attrs,
                    exceptions=requests.exceptions.RequestException,
                    tries=7,
                    delay=1,
                    jitter=2,
                    logger=LOG,
                )
    LOG.info(f"Finished handling image {image_name}")
