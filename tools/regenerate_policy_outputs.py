import yaml
import logging
import os

from rockoon import layers
from rockoon import resource_view

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

OUTPUT_DIR = "tests/fixtures/network_policies/output"

osdpl = yaml.safe_load(open("tests/fixtures/openstackdeployment.yaml"))
mspec = layers.merge_spec(osdpl["spec"], LOG)
child_view = resource_view.ChildObjectView(mspec)
network_policy = child_view.get_network_policies()

service_policies = {}
for identifier, policies in network_policy["ingress"].items():
    service, chart, kind, name = identifier.split(':')
    service_policies.setdefault(service, {})
    service_policies[service][identifier] = policies

for service, policies in service_policies.items():
    out_template = os.path.join(OUTPUT_DIR, f"{service}.yaml")
    with open(out_template, "w") as f:
        yaml.dump(policies, f)
