{{- $envAll := . }}
- username: {{ $envAll.Values.conf.tempest.auth.admin_username }}
  password: {{ $envAll.Values.conf.tempest.auth.admin_password }}
  roles: ["admin"]
  system: all
  user_domain_name: {{ $envAll.Values.conf.tempest.auth.admin_domain_name }}

- username: tempest-system-reader-manual
  user_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  password: tempest-system-reader-manual-password
  roles: ["reader"]
  system: all

{{- range $idx, $pr := until (add $envAll.Values.conf.static_accounts.project_count_with_network $envAll.Values.conf.static_accounts.project_count_without_network | int)}}
{{- range $idx, $usr := until ($envAll.Values.conf.static_accounts.user_count | int ) }}
{{- if $envAll.Values.conf.static_accounts.create_reader_user }}
- username: tempest-reader-manual-{{ $pr }}-{{ $usr }}
  user_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  project_name: tempest-manual-{{ $pr }}
  project_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  password: tempest-reader-manual-password
  roles: ["reader"]
  {{- if lt $pr ($envAll.Values.conf.static_accounts.project_count_with_network | int) }}
  resources:
   network: tempest-manual-{{ $pr }}
  {{- end }}
{{- end }}

- username: tempest-manual-{{ $pr }}-{{ $usr }}
  user_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  project_name: tempest-manual-{{ $pr }}
  project_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  password: tempest-manual-password
  roles: {{ $envAll.Values.conf.static_accounts.regular_roles | toJson }}
  {{- if lt $pr ($envAll.Values.conf.static_accounts.project_count_with_network | int) }}
  resources:
   network: tempest-manual-{{ $pr }}
  {{- end }}

- username: tempest-admin-manual-{{ $pr }}-{{ $usr }}
  user_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  project_name: tempest-manual-{{ $pr }}
  project_domain_name: {{ $envAll.Values.conf.static_accounts.domain_name }}
  password: tempest-admin-manual-password
  roles: {{ $envAll.Values.conf.static_accounts.admin_roles | toJson }}
  {{- if lt $pr ($envAll.Values.conf.static_accounts.project_count_with_network | int) }}
  resources:
   network: tempest-manual-{{ $pr }}
  {{- end }}

{{ end }}
{{ end }}
