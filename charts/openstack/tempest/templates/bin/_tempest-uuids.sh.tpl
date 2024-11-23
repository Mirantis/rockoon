#!/bin/bash

{{/*
Copyright 2017 The Openstack-Helm Authors.

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

# Mask permissions to files 416 dirs 0750
umask 0027

TEMPEST_CONF_ORIG="/etc/tempest/tempest-orig.conf"
TEMPEST_CONF="/etc/tempest/tempest.conf"

source /tmp/functions.sh

cp $TEMPEST_CONF_ORIG $TEMPEST_CONF

{{ if not (empty .Values.conf.convert_to_uuid) }}
{{- $publicNetworkId := .Values.conf.convert_to_uuid.network.public_network_id }}
# Get project network id
PUBLIC_NETWORK_ID=$(openstack network show {{ $publicNetworkId }} -f value -c id)

# Check if project network id not set
die_if_not_set $LINENO PUBLIC_NETWORK_ID "Failure getting PUBLIC_NETWORK_ID for {{ $publicNetworkId }}"

# Set project network id to tempest configuration file
iniset $TEMPEST_CONF network public_network_id $PUBLIC_NETWORK_ID

{{- if .Values.conf.convert_to_uuid.network.public_subnet_id }}
{{- $subnetId := .Values.conf.convert_to_uuid.network.public_subnet_id }}
SUBNET_ID=$(openstack subnet show {{ $subnetId }} -f value -c id)
die_if_not_set $LINENO SUBNET_ID "Failure getting SUBNET_ID for {{ $subnetId }}"
iniset $TEMPEST_CONF network subnet_id $SUBNET_ID
{{- end }}

{{- $imageRef := .Values.conf.convert_to_uuid.compute.image_ref }}
# Get image ref id
IMAGE_REF=$(openstack image show {{ $imageRef }} -f value -c id)

# Check if image ref id not set
die_if_not_set $LINENO IMAGE_REF "Failure getting IMAGE_REF for {{ $imageRef }}"

# Set image ref id to tempest configuration file
iniset $TEMPEST_CONF compute image_ref $IMAGE_REF

{{- $imageRefAlt := .Values.conf.convert_to_uuid.compute.image_ref_alt }}
# Get image ref alt id
IMAGE_REF_ALT=$(openstack image show {{ $imageRefAlt }} -f value -c id)

# Check if image ref alt not set
die_if_not_set $LINENO IMAGE_REF_ALT "Failure getting IMAGE_REF_ALT for {{ $imageRefAlt }}"

# Set image ref alt id to tempest configuration file
iniset $TEMPEST_CONF compute image_ref_alt $IMAGE_REF_ALT

{{- if .Values.conf.convert_to_uuid.compute.image_raw_ref }}
{{- $imageRawRef := .Values.conf.convert_to_uuid.compute.image_raw_ref }}
# Get image ref raw id
IMAGE_RAW_REF=$(openstack image show {{ $imageRawRef }} -f value -c id)

# Check if image ref raw not set
die_if_not_set $LINENO IMAGE_RAW_REF "Failure getting IMAGE_RAW_REF for {{ $imageRawRef }}"

# Set image ref raw id to tempest configuration file
iniset $TEMPEST_CONF compute image_raw_ref $IMAGE_RAW_REF
{{- end }}

{{- if .Values.conf.convert_to_uuid.compute.windows10_image_ref }}
{{- $windows10ImageRef := .Values.conf.convert_to_uuid.compute.windows10_image_ref }}
WINDOWS10_IMAGE_REF=$(openstack image show {{ $windows10ImageRef }} -f value -c id)
die_if_not_set $LINENO WINDOWS10_IMAGE_REF "Failure getting WINDOWS10_IMAGE_REF for {{ $windows10ImageRef }}"
iniset $TEMPEST_CONF compute windows10_image_ref $WINDOWS10_IMAGE_REF
{{- end }}

{{- if .Values.conf.convert_to_uuid.compute.windows11_image_ref }}
{{- $windows11ImageRef := .Values.conf.convert_to_uuid.compute.windows11_image_ref }}
WINDOWS11_IMAGE_REF=$(openstack image show {{ $windows11ImageRef }} -f value -c id)
die_if_not_set $LINENO WINDOWS11_IMAGE_REF "Failure getting WINDOWS11_IMAGE_REF for {{ $windows11ImageRef }}"
iniset $TEMPEST_CONF compute windows11_image_ref $WINDOWS11_IMAGE_REF
{{- end }}

{{- $flavorRef := .Values.conf.convert_to_uuid.compute.flavor_ref }}
# Get flavor ref id
FLAVOR_REF=$(openstack flavor show {{ $flavorRef }} -f value -c id)

# Check if flavor ref id not set
die_if_not_set $LINENO FLAVOR_REF "Failure getting FLAVOR_REF for {{ $flavorRef }}"

# Set flavor ref id to tempest configuration file
iniset $TEMPEST_CONF compute flavor_ref $FLAVOR_REF

{{- $flavorRefAlt := .Values.conf.convert_to_uuid.compute.flavor_ref_alt }}
# Get flavor ref alt id
FLAVOR_REF_ALT=$(openstack flavor show {{ $flavorRefAlt }} -f value -c id)

# Check if flavor ref alt not set
die_if_not_set $LINENO FLAVOR_REF_ALT "Failure getting FLAVOR_REF_ALT for {{ $flavorRefAlt }}"

# Set flavor ref alt id to tempest configuration file
iniset $TEMPEST_CONF compute flavor_ref_alt $FLAVOR_REF_ALT

{{- $flavorFulRef := .Values.conf.convert_to_uuid.compute.image_full_flavor_ref }}
IMAGE_FULL_FLAVOR_REF=$(openstack flavor show {{ $flavorFulRef }} -f value -c id)

# Check if flavor ref alt not set
die_if_not_set $LINENO IMAGE_FULL_FLAVOR_REF "Failure getting IMAGE_FULL_FLAVOR_REF  for {{ $flavorFulRef }}"

# Set flavor ref alt id to tempest configuration file
iniset $TEMPEST_CONF compute image_full_flavor_ref $IMAGE_FULL_FLAVOR_REF

{{- if .Values.conf.convert_to_uuid.compute.windows10_flavor_ref }}
{{- $windows10FlavorRef := .Values.conf.convert_to_uuid.compute.windows10_flavor_ref }}
WINDOWS10_FLAVOR_REF=$(openstack flavor show {{ $windows10FlavorRef }} -f value -c id)
die_if_not_set $LINENO WINDOWS10_FLAVOR_REF "Failure getting WINDOWS10_FLAVOR_REF for {{ $windows10FlavorRef }}"
iniset $TEMPEST_CONF compute windows10_flavor_ref $WINDOWS10_FLAVOR_REF
{{- end }}

{{- if .Values.conf.convert_to_uuid.compute.windows11_flavor_ref }}
{{- $windows11FlavorRef := .Values.conf.convert_to_uuid.compute.windows11_flavor_ref }}
WINDOWS11_FLAVOR_REF=$(openstack flavor show {{ $windows11FlavorRef }} -f value -c id)
die_if_not_set $LINENO WINDOWS11_FLAVOR_REF "Failure getting WINDOWS11_FLAVOR_REF for {{ $windows11FlavorRef }}"
iniset $TEMPEST_CONF compute windows11_flavor_ref $WINDOWS11_FLAVOR_REF
{{- end }}

{{- $imageFullRef := .Values.conf.convert_to_uuid.compute.image_full_ref }}
# Get image ref alt id
IMAGE_FULL_REF=$(openstack image show {{ $imageFullRef }} -f value -c id)

# Check if image ref alt not set
die_if_not_set $LINENO IMAGE_FULL_REF "Failure getting IMAGE_FULL_REF for {{ $imageFullRef }}"

# Set image ref alt id to tempest configuration file
iniset $TEMPEST_CONF compute image_full_ref $IMAGE_FULL_REF

{{- if not (index .Values.conf.tempest "neutron_plugin_options" "advanced_image_flavor_ref") }}
iniset $TEMPEST_CONF neutron_plugin_options advanced_image_flavor_ref $IMAGE_FULL_FLAVOR_REF
{{- end }}
{{- if not (index .Values.conf.tempest "neutron_plugin_options" "advanced_image_ref") }}
iniset $TEMPEST_CONF neutron_plugin_options advanced_image_ref $IMAGE_FULL_REF
{{- end }}

if [[ ! -f /var/lib/tempest/data/{{ $imageRef }} ]]; then
  openstack image save --file /var/lib/tempest/data/$IMAGE_REF  $IMAGE_REF
fi
# Set local image parameters
iniset $TEMPEST_CONF scenario img_file /var/lib/tempest/data/$IMAGE_REF

{{- end }}

{{- if hasKey .Values.conf.tempest.dns "nameservers" }}
iniset $TEMPEST_CONF dns nameservers {{ include "helm-toolkit.utils.joinListWithComma" .Values.conf.tempest.dns.nameservers }}
{{- else }}
{{ $backend_dns_service_name_var := upper (printf "%s_%s_%s" (.Values.endpoints.powerdns.hosts.internal | replace "-" "_") "SERVICE" "HOST") }}
iniset $TEMPEST_CONF dns nameservers ${{ $backend_dns_service_name_var }}
{{- end }}

{{- $identityDefaultDomainId := .Values.conf.convert_to_uuid.identity.default_domain_id }}
# Get id of default domain
IDENTITY_DEFAULT_DOMAIN_ID=$(openstack domain show {{ $identityDefaultDomainId }} -f value -c id)

die_if_not_set $LINENO IDENTITY_DEFAULT_DOMAIN_ID "Failure getting IDENTITY_DEFAULT_DOMAIN_ID for {{ $identityDefaultDomainId }}"

iniset $TEMPEST_CONF identity default_domain_id $IDENTITY_DEFAULT_DOMAIN_ID

# Get fixed/baremetal network id for load balancer tests
{{- if and (hasKey .Values.conf.tempest.auth "create_isolated_networks") (hasKey .Values.conf.tempest "compute") }}
{{- if and .Values.conf.tempest.compute.fixed_network_name (eq .Values.conf.tempest.auth.create_isolated_networks false) }}
{{- $fixedNetworkName := .Values.conf.tempest.compute.fixed_network_name }}
FIXED_NETWORK_ID=$(openstack network show {{ $fixedNetworkName }} -f value -c id)
die_if_not_set $LINENO FIXED_NETWORK_ID "Failure getting FIXED_NETWORK_ID for {{ $fixedNetworkName }}"
iniset $TEMPEST_CONF load_balancer test_network_override $FIXED_NETWORK_ID
{{- end }}
{{- end }}

# Encryption settings
{{- if .Values.conf.tempest.service_available.cinder }}
{{-   if not (index .Values.conf.tempest "compute-feature-enabled" "attach_encrypted_volume") }}
encrypted_volume_type=$(openstack volume type list  --encryption-type |grep cipher= |grep "provider='luks'"| awk '{print $4}' | head -1)
if [[ -n $encrypted_volume_type ]]; then
    iniset $TEMPEST_CONF compute-feature-enabled attach_encrypted_volume True
{{-     if not (index .Values.conf.tempest "volume" "volume_type_luks") }}
    iniset $TEMPEST_CONF volume volume_type_luks $encrypted_volume_type
{{-     end }}
fi
{{-   end }}

{{-   if not (index .Values.conf.tempest "compute-feature-enabled" "block_migrate_cinder_iscsi") }}
{{-     if (index .Values.conf.tempest "volume" "volume_type") }}
volume_type_name={{ .Values.conf.tempest.volume.volume_type }}
{{-     end }}
if [[ -z "$volume_type_name" ]]; then
    volume_type_name=$(openstack volume type list  --default -f value -c Name)
fi
volume_type_details=$(openstack volume type show ${volume_type_name})

if [[ ${volume_type_details} == *"lvm"* ]]; then
    iniset $TEMPEST_CONF compute-feature-enabled  block_migrate_cinder_iscsi True
    iniset $TEMPEST_CONF volume storage_protocol "iSCSI"
fi
if [[ ${volume_type_details} == *"-nfs"* ]]; then
    iniset $TEMPEST_CONF volume-feature-enabled extend_attached_volume False
fi
{{-   end }}
{{- end }}

# Volume and snapshot naming for Ceph envs
storage_protocol={{ .Values.conf.tempest.volume.storage_protocol }}
if [[ "storage_protocol" == "ceph" ]]; then
    iniset $TEMPEST_CONF volume manage_snapshot_ref "source-name, snapshot-%s"
    iniset $TEMPEST_CONF volume manage_volume_ref "source-name, %s"
fi

# Share settings
{{- $shareClientVMFlavorRef := .Values.conf.convert_to_uuid.share.client_vm_flavor_ref }}
# Get flavor ref id
if [[ -n  "{{ $shareClientVMFlavorRef }}" ]]; then
  SHARE_FLAVOR_REF=$(openstack flavor show {{ $shareClientVMFlavorRef }} -f value -c id)
  iniset $TEMPEST_CONF share client_vm_flavor_ref $SHARE_FLAVOR_REF
fi

#Get tld list
EXISTING_TLDS=$(openstack tld list -f value -c name | tr '\n' ',' | sed 's/,$//')
iniset $TEMPEST_CONF dns existing_tlds $EXISTING_TLDS
