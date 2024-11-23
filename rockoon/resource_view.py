from rockoon import layers


class ChildObject:
    def __init__(self, service, chart, kind, name, meta=None):
        self.service = service
        self.chart = chart
        self.kind = kind
        self.name = name
        self.meta = meta or {}
        self.connections = self.init_connections()

    @property
    def identifier(self):
        return f"{self.service}:{self.chart}:{self.kind}:{self.name}"

    def init_connections(self):
        connections = {"ingress": [], "egress": []}
        for connection in self.meta.get("connections", {}).get("egress", []):
            to_child_object = connection.get("to_child_object")
            if to_child_object:
                src_ident = self.identifier
                dst_ident = f"{to_child_object['service']}:{to_child_object['chart']}:{to_child_object['kind']}:{to_child_object['name']}"
                connections["egress"].append(
                    ChildObjectConnection(
                        src_ident, dst_ident, to_child_object["ports"]
                    )
                )
        return connections

    def get_port(self, name):
        for port in self.meta.get("ports", []):
            if port["name"] == name:
                return port

    def get_pod_labels(self):
        return self.meta["pod_labels"]

    def get_np_ports(self, p_list):
        ports = []
        for port in self.meta.get("ports", []):
            if port["name"] in p_list:
                ports.append(
                    {"protocol": port["protocol"], "port": port["port"]}
                )
        return ports


class ChildObjectConnection:
    def __init__(self, src_ident, dst_ident, ports):
        self.src_ident = src_ident
        self.dst_ident = dst_ident
        self.ports = ports

    def np_from(self, childs):
        src = childs[self.src_ident]
        return [{"podSelector": {"matchLabels": src.get_pod_labels()}}]

    def np_to(self, childs):
        dst = childs[self.dst_ident]
        return [{"podSelector": {"matchLabels": dst.get_pod_labels()}}]

    def np_ports(self, childs):
        dst = childs[self.dst_ident]
        ports = []
        for port in self.ports:
            dst_port = dst.get_port(port)
            ports.append(
                {"protocol": dst_port["protocol"], "port": dst_port["port"]}
            )
        return ports


class ChildObjectView:
    def __init__(self, mspec):
        self.mspec = mspec
        self.childs = self._init_childs()
        self.network_policies = self.get_network_policies()

    def _init_childs(self):
        res = {}
        for service, charts in layers.get_child_tree(self.mspec).items():
            for chart, kinds in charts.items():
                for kind, childs in kinds.items():
                    for child_name, child_meta in childs.items():
                        child = ChildObject(
                            service, chart, kind, child_name, child_meta
                        )
                        res[child.identifier] = child
        return res

    def get_child_meta(self, service, chart, kind, name):
        child_ident = f"{service}:{chart}:{kind}:{name}"
        return self.childs[child_ident].meta

    def squash_policies(self, policies):
        # Squash policies. Policies that have same port range may be squashed to use multiple podSelectors
        squashed_policies = []
        policy_from = {}
        ports_hashes = {}
        for policy in policies:
            ports_hash = layers.spec_hash(policy["ports"])
            ports_hashes[ports_hash] = policy["ports"]
            policy_from.setdefault(ports_hash, [])
            policy_from[ports_hash].extend(policy["from"])
        for ports_hash, ports in ports_hashes.items():
            squashed_policies.append(
                {"from": policy_from[ports_hash], "ports": ports}
            )
        return squashed_policies

    def get_network_policies(self):
        network_policies_egress = {}
        # TODO(vsaienko): implement egress direction.

        # Construct ingress connection based on egress connection from the tree
        ingress_policies = {}
        for child_identifier, child in self.childs.items():
            for connection in child.connections["egress"]:
                ingress_policies.setdefault(connection.dst_ident, [])
                policy = {
                    "from": connection.np_from(self.childs),
                    "ports": connection.np_ports(self.childs),
                }
                ingress_policies[connection.dst_ident].append(policy)

        # Squash policies. Policies that have same port range may be squashed to use multiple podSelectors
        squashed_policies = {}
        for child_identifier, policies in ingress_policies.items():
            squashed_policies[child_identifier] = self.squash_policies(
                policies
            )
        return {
            "ingress": squashed_policies,
            "egress": network_policies_egress,
        }
