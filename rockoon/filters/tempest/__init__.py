from rockoon.filters.tempest.conf import SECTIONS
from rockoon import utils


@utils.log_exception_and_raise
def generate_tempest_config(spec, helmbundle_spec):
    config = {}

    for ts in SECTIONS:
        ts_inst = ts(spec, helmbundle_spec)
        if not ts_inst.enabled:
            continue
        config[ts_inst.name] = {}
        opts = {}
        for opt in ts_inst.options:
            val = getattr(ts_inst, opt)
            if val is not None:
                opts[opt] = val

        config[ts_inst.name] = opts
    return config
