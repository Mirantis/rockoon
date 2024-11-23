{{- $envAll := . -}}
heat_template_version: queens
description: Template to generate static accounts for tempest

parameters:
    domain_name:
      type: string
      default: {{ $envAll.Values.conf.static_accounts.domain_name }}
    public_network_name:
      type: string
      default: {{ $envAll.Values.conf.convert_to_uuid.network.public_network_id }}

resources:

  # NOTE(pas-ha) Heat User/Group resources can not assign roles in system scope yet
  # https://storyboard.openstack.org/#!/story/2010223
  # so we will do it in the script that creates this stack
  tempest_system_reader:
    type: OS::Keystone::User
    properties:
      enabled: true
      domain: { get_param: domain_name }
      name: tempest-system-reader-manual
      password: tempest-system-reader-manual-password
      email: tempest-system-reader-manual@test.com
      description: Tempest system reader user

{{- range $idx, $pr := until (add $envAll.Values.conf.static_accounts.project_count_with_network $envAll.Values.conf.static_accounts.project_count_without_network | int)}}

  tempest_project_{{ $pr }}:
    type: OS::Keystone::Project
    properties:
      description: Tempest project {{ $pr }}
      domain: { get_param: domain_name }
      enabled: true
      name: tempest-manual-{{ $pr }}

  tempest_project_{{ $pr }}_quota:
    depends_on:
    - tempest_project_{{ $pr }}
    type: OS::Nova::Quota
    properties:
      cores: {{ $envAll.Values.conf.static_accounts.quotas.cores }}
      instances: {{ $envAll.Values.conf.static_accounts.quotas.instances }}
      key_pairs: {{ $envAll.Values.conf.static_accounts.quotas.key_pairs }}
      metadata_items: {{ $envAll.Values.conf.static_accounts.quotas.metadata_items }}
      project: { get_attr: [tempest_project_{{ $pr }}, name] }
      ram: {{ $envAll.Values.conf.static_accounts.quotas.ram }}
      server_group_members: {{ $envAll.Values.conf.static_accounts.quotas.server_group_members }}
      server_groups: {{ $envAll.Values.conf.static_accounts.quotas.server_groups }}

{{- range $idx, $usr := until ( $envAll.Values.conf.static_accounts.user_count | int ) }}

{{- if $envAll.Values.conf.static_accounts.create_reader_user }}
  tempest_reader_user_{{ $pr }}_{{ $usr }}:
    depends_on:
    - tempest_project_{{ $pr }}_quota
    - tempest_user_{{ $pr }}_{{ $usr }}
    type: OS::Keystone::User
    properties:
      default_project: { get_resource: tempest_project_{{ $pr }} }
      description: Tempest user {{ $pr }}
      domain: { get_param: domain_name }
      email: tempest-user-reader-manual-{{ $pr }}@test.com
      enabled: true
      name: tempest-reader-manual-{{ $pr }}-{{ $usr }}
      password: tempest-reader-manual-password
      roles: [{"role": reader, "project": { get_resource: tempest_project_{{ $pr }} } }]
{{- end }}

  tempest_user_{{ $pr }}_{{ $usr }}:
    type: OS::Keystone::User
    properties:
      default_project: { get_resource: tempest_project_{{ $pr }} }
      description: Tempest user {{ $pr }}
      domain: { get_param: domain_name }
      email: tempest-user-manual-{{ $pr }}@test.com
      enabled: true
      name: tempest-manual-{{ $pr }}-{{ $usr }}
      password: tempest-manual-password
      roles: [{"role": member, "project": { get_resource: tempest_project_{{ $pr }} } }, {"role": creator, "project": { get_resource: tempest_project_{{ $pr }} } }]

  tempest_admin_user_{{ $pr }}_{{ $usr }}:
    depends_on:
    - tempest_user_{{ $pr }}_{{ $usr }}
    type: OS::Keystone::User
    properties:
      default_project: { get_resource: tempest_project_{{ $pr }} }
      description: Tempest admin user {{ $pr }}
      domain: { get_param: domain_name }
      email: tempest-user-admin-manual-{{ $pr }}@test.com
      enabled: true
      name: tempest-admin-manual-{{ $pr }}-{{ $usr }}
      password: tempest-admin-manual-password
      roles: [{"role": admin, "project": { get_resource: tempest_project_{{ $pr }} } }]

{{ end }}

{{- if lt $pr ($envAll.Values.conf.static_accounts.project_count_with_network | int) }}
  tempest_network_{{ $pr }}:
    depends_on:
    - tempest_project_{{ $pr }}_quota
    type: OS::Neutron::Net
    properties:
      admin_state_up: true
      dns_domain: test-{{ $pr }}.com.
      name: tempest-manual-{{ $pr }}
      tenant_id: { get_resource: tempest_project_{{ $pr }} }

  tempest_subnet_{{ $pr }}:
    type: OS::Neutron::Subnet
    properties:
      allocation_pools: [{"start": 192.168.{{ $pr }}.10, "end": 192.168.{{ $pr }}.254}]
      cidr: 192.168.{{ $pr }}.0/24
      enable_dhcp: true
      name: tempest-manual-{{ $pr }}
      network: { get_resource: tempest_network_{{ $pr }} }
      tenant_id: { get_resource: tempest_project_{{ $pr }} }

  tempest_router_{{ $pr }}:
    type: OS::Neutron::Router
    properties:
      admin_state_up: true
      external_gateway_info: {"network": { get_param: public_network_name }}
      name: tempest-manual{{ $pr }}
      value_specs: {'tenant_id': { get_resource: tempest_project_{{ $pr }} } }


  tempest_router_interface_{{ $pr }}:
    type: OS::Neutron::RouterInterface
    properties:
      router: { get_resource: tempest_router_{{ $pr }} }
      subnet: { get_resource: tempest_subnet_{{ $pr }} }
{{- end }}

{{ end }}

outputs:
  secret_ca:
    value: { get_resource: tempest_secret_CA }
  secret_intermediate_a:
    value: { get_resource: tempest_secret_IntermediateA }
  secret_intermediate_b:
    value: { get_resource: tempest_secret_IntermediateB }
  secret_client:
    value: { get_resource: tempest_secret_Client }
