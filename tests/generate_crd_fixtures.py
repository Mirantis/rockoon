import logging
import sys

import yaml

from rockoon import layers


def main(args):
    n = len(args)
    os_version = "stein"
    openstackdeployment_file = (
        f"examples/{os_version}/core-ceph-local-non-dvr.yaml"
    )
    openstackdeployment = yaml.safe_load(open(openstackdeployment_file))
    preset = openstackdeployment["spec"]["preset"]
    size = openstackdeployment["spec"]["size"]
    base = yaml.safe_load(
        layers.ENV.get_template(f"preset/{preset}.yaml").render()
    )
    artifacts = yaml.safe_load(
        layers.ENV.get_template("artifacts.yaml").render()
    )
    sizing = yaml.safe_load(
        layers.ENV.get_template(f"size/{size}.yaml").render()
    )
    openstackdeployment["spec"] = layers.merger.merge(
        base, openstackdeployment["spec"]
    )
    openstackdeployment["spec"] = layers.merger.merge(base, artifacts)
    openstackdeployment["spec"] = layers.merger.merge(base, sizing)
    openstackdeployment["spec"]["features"]["ssl"]["public_endpoints"][
        "enabled"
    ] = False

    if n == 1:
        print(yaml.dump(openstackdeployment))
    else:
        service = args[1]
        template_only = args[2:3]
        func = (
            layers.render_service_template
            if template_only
            else layers.render_all
        )
        if template_only:
            openstackdeployment["spec"]["common"] = {
                "infra": {},
                "openstack": {"repo": ""},
            }
        print(
            yaml.dump(
                func(
                    service,
                    openstackdeployment,
                    openstackdeployment["metadata"],
                    openstackdeployment["spec"],
                    logging,
                )
            )
        )


if __name__ == "__main__":
    main(sys.argv)
