from rockoon.filters.tempest import base_section


class NetworkFeatureEnabled(base_section.BaseSection):
    name = "network-feature-enabled"
    options = [
        "api_extensions",
        "available_features",
        "floating_ips",
        "ipv6",
        "ipv6_subnet_attributes",
        "port_admin_state_change",
        "port_security",
    ]

    @property
    def api_extensions(self):
        api_extensions_default = [
            "binding",
            "external-net",
            "quotas",
            "quota_details",
            "provider",
            "standard-attr-tag",
            "standard-attr-timestamp",
            "service-type",
            "port-security",
            "extra_dhcp_opt",
            "pagination",
            "sorting",
            "security-group",
            "standard-attr-description",
            "router",
            "allowed-address-pairs",
            "project-id",
        ]

        if self.get_spec_item("features.neutron.backend", "ml2") == "ml2":
            api_extensions_default.extend(
                [
                    "ip-substring-filtering",
                    "l3-ha",
                    "l3-flavors",
                    "l3_agent_scheduler",
                    "dhcp_agent_scheduler",
                ]
            )
            if self.os_version_compare("ussuri", "ge"):
                api_extensions_default.extend(
                    [
                        "rbac-subnetpool",
                    ]
                )
            if self.os_version_compare("wallaby", "ge"):
                api_extensions_default.extend(
                    [
                        "rbac-address-group",
                    ]
                )

        if self.get_spec_item("features.neutron.backend") == "ml2":
            api_extensions_default.extend(
                [
                    "dvr",
                ]
            )

        if self.get_spec_item("features.neutron.backend") in [
            "ml2",
            "ml2/ovn",
        ]:
            api_extensions_default.extend(
                [
                    "auto-allocated-topology",
                    "network-ip-availability",
                    "network_availability_zone",
                    "subnet_allocation",
                    "flavors",
                    "filter-validation",
                    "availability_zone",
                    "multi-provider",
                    "subnet-service-types",
                    "standard-attr-revisions",
                    "router_availability_zone",
                    "dns-domain-ports",
                    "dns-integration",
                    "default-subnetpools",
                    "ext-gw-mode",
                    "agent",
                    "net-mtu",
                    "address-scope",
                    "extraroute",
                    "rbac-policies",
                    "qos",
                    "qos-bw-limit-direction",
                    "qos-bw-minimum-ingress",
                    "qos-default",
                    "qos-fip",
                    "qos-gateway-ip",
                    "qos-rule-type-details",
                    "qos-rules-alias",
                    "subnetpool-prefix-ops",
                    "floatingip-pools",
                ]
            )

            if self.os_version_compare("ussuri", "ge"):
                api_extensions_default.extend(
                    [
                        "rbac-address-scope",
                        "rbac-security-groups",
                        "stateful-security-group",
                        "fip-port-details",
                        "port-mac-address-regenerate",
                        "qos-port-network-policy",
                    ],
                )
            if self.os_version_compare("victoria", "ge"):
                api_extensions_default.extend(["net-mtu-writable"])
            if self.os_version_compare("wallaby", "ge"):
                api_extensions_default.extend(
                    [
                        "address-group",
                        "security-groups-remote-address-group",
                    ],
                )
            if self.os_version_compare("xena", "ge"):
                api_extensions_default.extend(["port-resource-request"])
            if self.os_version_compare("yoga", "ge"):
                api_extensions_default.extend(
                    [
                        "port-resource-request-groups",
                        "qos-pps-minimum",
                        "qos-pps-minimum-rule-alias",
                        "qos-pps",
                    ],
                )
            if self.os_version_compare("antelope", "ge"):
                if self.get_values_item(
                    "neutron", "conf.neutron.DEFAULT.vlan_transparent", False
                ):
                    api_extensions_default.append("vlan-transparent")
        if self.os_version_compare("caracal", "ge"):
            if not self.tf_enabled():
                api_extensions_default.extend(
                    ["security-groups-default-rules"]
                )

        if self.get_spec_item("features.neutron.bgpvpn.enabled"):
            api_extensions_default.extend(
                ["bgpvpn", "bgpvpn-routes-control", "bgpvpn-vni"]
            )
        if self.get_spec_item("features.neutron.extensions.vpnaas.enabled"):
            api_extensions_default.extend(["vpnaas"])
            api_extensions_default.remove("filter-validation")
        if self.get_spec_item(
            "features.neutron.extensions.dynamic_routing.enabled"
        ):
            api_extensions_default.extend(["bgp"])

        if self.tf_enabled():
            if self.os_version_compare("victoria", "ge"):
                api_extensions_default.extend(
                    ["net-mtu", "net-mtu-writable"],
                )
        if self.get_spec_item(
            "features.neutron.extensions.portprober.enabled", False
        ):
            api_extensions_default.extend(["portprober"])

        if self.os_version_compare("antelope", "ge") and (
            self.tf_enabled()
            or self.get_spec_item(
                "features.neutron.extensions.trunk.enabled", True
            )
        ):
            api_extensions_default.extend(["trunk"])

        return ", ".join(api_extensions_default)

    @property
    def available_features(self):
        if self.tf_enabled():
            return ""

    @property
    def floating_ips(self):
        pass

    @property
    def ipv6(self):
        return True

    @property
    def ipv6_subnet_attributes(self):
        return True

    @property
    def port_admin_state_change(self):
        pass

    @property
    def port_security(self):
        # TODO:(PRODX-1206)Need to generate 'api_extensions' in openstack-networking helmbundle.
        # In this case we should check that 'port_security' locate in 'api_extensions'.
        if self.is_service_enabled("neutron"):
            return True
