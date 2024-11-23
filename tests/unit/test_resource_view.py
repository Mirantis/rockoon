import logging
import glob
import yaml

import pytest

logger = logging.getLogger(__name__)

OUTPUT_DIR = "tests/fixtures/network_policies/output"


def get_output_templates():
    res = []
    for filename in glob.glob(f"{OUTPUT_DIR}/*.yaml"):
        res.append(filename)
    return res


@pytest.mark.parametrize("out_template", get_output_templates())
def test_network_policy_ingress(
    out_template,
    child_view,
):
    network_policy = child_view.get_network_policies()
    service = out_template.split("/")[-1].split(".")[0]
    service_policies = {
        k: v
        for k, v in network_policy["ingress"].items()
        if k.startswith(service)
    }
    with open(out_template, "r") as f:
        out = yaml.safe_load(f)
    assert out == service_policies


@pytest.mark.parametrize("out_template", get_output_templates())
def test_network_policy_eggress(
    out_template,
    child_view,
):
    network_policy = child_view.get_network_policies()
    assert {} == network_policy["egress"]
