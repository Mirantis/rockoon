#!/usr/bin/env python3
import functools

from rockoon import utils

LOG = utils.get_logger(__name__)


def generic_exception(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise e

    return wrapper
