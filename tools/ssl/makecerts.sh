#!/usr/bin/env bash
basedir=$(dirname "$0")
workdir=${basedir}/certs
mkdir -p ${workdir}
if [ ! -f "${workdir}/cfssl" ]; then
    curl -L https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -o ${workdir}/cfssl
fi
if [ ! -f "${workdir}/cfssljson" ]; then
    curl -L https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -o ${workdir}/cfssljson
fi
chmod +x ${workdir}/cfssl
chmod +x ${workdir}/cfssljson
${workdir}/cfssl gencert -initca ${basedir}/ca-csr.json | ${workdir}/cfssljson -bare ${workdir}/ca
${workdir}/cfssl gencert -ca=${workdir}/ca.pem -ca-key=${workdir}/ca-key.pem --config=${basedir}/ca-config.json -profile=kubernetes ${basedir}/server-csr.json | ${workdir}/cfssljson -bare ${workdir}/server
echo "Paste content of ${workdir}/server.pem as value for 'spec.features.ssl.public_endpoints.api_cert'"
echo "Paste content of ${workdir}/server-key.pem as value for 'spec.features.ssl.public_endpoints.api_key'"
echo "Paste content of ${workdir}/ca.pem as value for 'spec.features.ssl.public_endpoints.ca_cert key'"

input_file=$1

if [ -z ${input_file} ]; then
    exit 0
fi

if [ ! -f ${input_file} ]; then
    echo "Can't access ${input_file}, skipping modifications..."
    exit 0
fi

if [ ! -f "${workdir}/yq" ]; then
    curl -L https://github.com/mikefarah/yq/releases/download/2.4.1/yq_linux_amd64 -o ${workdir}/yq
fi
chmod +x ${workdir}/yq
echo "Adding certificates to OpenStackDeploymet YAML ${input_file} in place.."
${workdir}/yq w --inplace -- "${input_file}" spec.features.ssl.public_endpoints.api_cert "$(cat ${workdir}/server.pem)"
${workdir}/yq w --inplace -- "${input_file}" spec.features.ssl.public_endpoints.api_key "$(cat ${workdir}/server-key.pem)"
${workdir}/yq w --inplace -- "${input_file}" spec.features.ssl.public_endpoints.ca_cert "$(cat ${workdir}/ca.pem)"
