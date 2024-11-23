#!/bin/bash

{{/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/}}

set -ex

LIBVIRT_CERT_PATH="/etc/pki/libvirt"
LIBVIRT_KEY_PATH=${LIBVIRT_CERT_PATH}/private
CA_CERT_PATH="/etc/pki/CA"
QEMU_CERT_PATH="{{- .Values.conf.qemu.default_tls_x509_cert_dir -}}"
LISTEN_INTERFACE="{{- .Values.conf.dynamic_options.libvirt.listen_interface -}}"

declare -A NUMBITS_CERT VALID_DAYS_CERT SUBJECT_NAME_CERT TLS_CONF_HASH TLS_CONF_HASH_FILE
NUMBITS_CERT[server]="{{- .Values.conf.tls.libvirt.server.server.numbits -}}"
NUMBITS_CERT[client]="{{- .Values.conf.tls.libvirt.server.client.numbits -}}"
VALID_DAYS_CERT[server]="{{- .Values.conf.tls.libvirt.server.server.days -}}"
VALID_DAYS_CERT[client]="{{- .Values.conf.tls.libvirt.server.client.days -}}"
SUBJECT_NAME_CERT[server]="{{- .Values.conf.tls.libvirt.server.server.subject_name -}}"
SUBJECT_NAME_CERT[client]="{{- .Values.conf.tls.libvirt.server.client.subject_name -}}"
TLS_CONF_HASH[server]={{ .Values.conf.tls.libvirt.server.server | include "helm-toolkit.utils.get_hash" }}
TLS_CONF_HASH[client]={{ .Values.conf.tls.libvirt.server.client | include "helm-toolkit.utils.get_hash" }}
TLS_CONF_HASH_FILE[server]=${CA_CERT_PATH}/tls-server.conf.sha256
TLS_CONF_HASH_FILE[client]=${CA_CERT_PATH}/tls-client.conf.sha256

LISTEN_IP_ADDRESS=$(ip address show ${LISTEN_INTERFACE} | grep 'inet ' | awk '{print $2}' | awk -F "/" '{print $1}')

mkdir -p $LIBVIRT_CERT_PATH
mkdir -p $LIBVIRT_KEY_PATH
mkdir -p $QEMU_CERT_PATH
# copy CA cert and key to host directory mounted to ${CA_CERT_PATH}
# as libvirt expects to find cacert.pem at ${CA_CERT_PATH}/cacert.pem
cp /tmp/cacert.pem ${CA_CERT_PATH}/cacert.pem
cp /tmp/cakey.pem ${CA_CERT_PATH}/cakey.pem

function generate_cert {
    local cert_type=$1
    cat << EOF > ${LIBVIRT_CERT_PATH}/cert.conf
[local_san]
basicConstraints     = CA:FALSE
nsCertType           = ${cert_type}
nsComment            = "OpenSSL Generated ${cert_type} Certificate"
extendedKeyUsage     = ${cert_type}Auth
subjectKeyIdentifier = hash
subjectAltName       = @alt_names

[alt_names]
IP.1                 = $LISTEN_IP_ADDRESS
EOF

    openssl genrsa -out ${LIBVIRT_KEY_PATH}/${cert_type}key.pem ${NUMBITS_CERT[${cert_type}]}
    openssl req -new -sha256 -subj "${SUBJECT_NAME_CERT[${cert_type}]}" -key ${LIBVIRT_KEY_PATH}/${cert_type}key.pem -out ${LIBVIRT_CERT_PATH}/${cert_type}.csr
    openssl x509 -req -in ${LIBVIRT_CERT_PATH}/${cert_type}.csr -CA ${CA_CERT_PATH}/cacert.pem -CAkey ${CA_CERT_PATH}/cakey.pem -extfile ${LIBVIRT_CERT_PATH}/cert.conf -extensions local_san -CAcreateserial -days ${VALID_DAYS_CERT[${cert_type}]} -sha256 -out ${LIBVIRT_CERT_PATH}/${cert_type}cert.pem

    rm ${LIBVIRT_CERT_PATH}/${cert_type}.csr
    rm ${LIBVIRT_CERT_PATH}/cert.conf
    chmod 444 ${LIBVIRT_CERT_PATH}/${cert_type}cert.pem
    chmod 444 ${LIBVIRT_KEY_PATH}/${cert_type}key.pem
    cp ${LIBVIRT_CERT_PATH}/${cert_type}cert.pem ${QEMU_CERT_PATH}/${cert_type}-cert.pem
    cp ${LIBVIRT_KEY_PATH}/${cert_type}key.pem ${QEMU_CERT_PATH}/${cert_type}-key.pem
}

function write_conf_hash {
    local cert_type=$1
    echo ${TLS_CONF_HASH[${cert_type}]} > ${TLS_CONF_HASH_FILE[${cert_type}]}
}

for cert_type in "server" "client"; do
    if openssl verify -verbose -CAfile ${CA_CERT_PATH}/cacert.pem ${LIBVIRT_CERT_PATH}/${cert_type}cert.pem; then
        if [[ -f ${TLS_CONF_HASH_FILE[${cert_type}]} && $(cat ${TLS_CONF_HASH_FILE[${cert_type}]}) == ${TLS_CONF_HASH[${cert_type}]} ]]; then
            echo "TLS certificate ${cert_type} is up to date"
            continue
        fi
    fi
    generate_cert $cert_type
    write_conf_hash $cert_type
done

cp ${CA_CERT_PATH}/cacert.pem ${QEMU_CERT_PATH}/ca-cert.pem
