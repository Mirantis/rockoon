{{/*
Copyright 2019 Mirantis Inc.

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

{{/*
abstract: |
  This snippet adds kubernetes objects (init_container, volume) and also adds
  entry to configmao with script for loading kernel modules on hosts. For specifying the type
  of object need to pass "cm_entry" or "init_container" or "volume" value in "objectType" key.
examples:
  - values: |
      kernel:
        modules:
          l3_agent:
            module1:
              enabled: true
              params: "param1=param1_val param2=param2_val"
            module2:
              enabled: true
              params: "param1=param1_val1,param1_val2"
    usage_init_container: |
      {{ dict "envAll" $envAll "objectType" "init_container" "app" "neutron" "component" "l3_agent" "imageTag" "neutron_l3" | include "helm-toolkit.snippets.kubernetes_kernel_modules_objects" | indent 8 }}
    return_init_container: |
      - name: neutron-l3-agent-kernel-modules-init
        command:
          - /tmp/neutron-l3-agent-kernel-modules-init.sh
        image: docker-dev-kaas-virtual.docker.mirantis.net/openstack/neutron:antelope-jammy-20231013164438
        imagePullPolicy: IfNotPresent
        securityContext:
          runAsUser: 0
          runAsNonRoot: false
          capabilities:
            add:
              - SYS_MODULE
              - SYS_CHROOT
            drop:
              - ALL
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
        volumeMounts:
          - mountPath: /tmp/neutron-l3-agent-kernel-modules-init.sh
            name: neutron-bin
            readOnly: true
            subPath: neutron-l3-kernel-modules-init.sh
          - mountPath: /mnt/host-rootfs
            mountPropagation: HostToContainer
            name: host-rootfs
            readOnly: true
    usage_volume: |
      {{ dict "envAll" $envAll "objectType" "volume" "app" "neutron" "component" "l3_agent" | include "helm-toolkit.snippets.kubernetes_kernel_modules_objects" | indent 8 }}
    return_volume: |
      - hostPath:
          path: /
          type: Directory
        name: host-rootfs
    usage_cm_entry: |
      {{ dict "envAll" $envAll "objectType" "cm_entry" "app" "neutron" "component" "l3_agent" | include "helm-toolkit.snippets.kubernetes_kernel_modules_objects" | indent 2 }}
    return_cm_entry: |
      neutron-l3-agent-kernel-modules-init.sh: |
        #/bin/bash
        set -ex
        chroot /mnt/host-rootfs modprobe module1 param1=param1_val param2=param2_val
        chroot /mnt/host-rootfs modprobe module2 param1=param1_val1,param1_val2
*/}}

{{- define "helm-toolkit.snippets.kubernetes_kernel_modules_objects._default_security_context" -}}
Values:
  pod:
    security_context:
      kernel_modules_init:
        container:
          kernel_modules_init:
            runAsUser: 0
            runAsNonRoot: false
            capabilities:
              add:
               - SYS_MODULE
               - SYS_CHROOT
              drop:
               - ALL
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
{{- end -}}

{{- define "helm-toolkit.snippets.kubernetes_kernel_modules_objects" -}}
  {{- $envAll := index . "envAll" -}}
  {{- $objectType := index . "objectType" -}}
  {{- $app := index . "app" -}}
  {{- $component := index . "component" -}}
  {{- $manifest := printf "init_%s_kernel_modules" $component }}
  {{- $scriptPrefix := printf "%s-%s" $app (replace "_" "-" $component) }}
  {{- $modules := index $envAll.Values.kernel.modules $component | default dict }}
  {{/* Render modules only when at leat one module is enabled */}}
  {{- $modulesEnabled := dict }}
  {{- range $mod, $opts := $modules }}
    {{- if (index $opts "enabled") }}
      {{- $_ := set $modulesEnabled $mod $opts }}
    {{- end }}
  {{- end }}
  {{- if $modulesEnabled }}
    {{- if eq $objectType "init_container" }}
      {{- $imageTag := index . "imageTag" | default $component }}
      {{- $default_security_context := include "helm-toolkit.snippets.kubernetes_kernel_modules_objects._default_security_context" . | fromYaml }}
      {{- $patchedEnvAll := mergeOverwrite $default_security_context $envAll }}
- name: {{ $scriptPrefix }}-kernel-modules-init
{{ dict "envAll" $patchedEnvAll "application" "kernel_modules_init" "container" "kernel_modules_init" | include "helm-toolkit.snippets.kubernetes_container_security_context" | indent 2 }}
{{ tuple $envAll $imageTag | include "helm-toolkit.snippets.image" | indent 2}}
  command:
    - /tmp/{{ $scriptPrefix }}-kernel-modules-init.sh
  volumeMounts:
    - name: {{ $app }}-bin
      mountPath: /tmp/{{ $scriptPrefix }}-kernel-modules-init.sh
      subPath: {{ $scriptPrefix }}-kernel-modules-init.sh
      readOnly: true
    - mountPath: /mnt/host-rootfs
      mountPropagation: HostToContainer
      name: host-rootfs
      readOnly: true
    {{- end }}
    {{- if eq $objectType "volume" }}
- hostPath:
    path: /
    type: Directory
  name: host-rootfs
    {{- end }}
    {{- if eq $objectType "cm_entry" }}
{{ $scriptPrefix }}-kernel-modules-init.sh: |
  #!/bin/bash
  set -ex
      {{- range $mod, $opts := $modulesEnabled }}
        {{- $params := index $opts "params" }}
  chroot /mnt/host-rootfs modprobe {{ $mod }} {{ $params }}
      {{- end }}
    {{- end }}
  {{- end }}
{{- end }}
