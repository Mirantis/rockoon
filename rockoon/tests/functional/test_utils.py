import time
import logging

LOG = logging.getLogger(__name__)


def call_until_true(func, duration, sleep_for, *args, **kwargs):
    """Call the given function until it returns True (and return True)

    or until the specified duration (in seconds) elapses (and return False).

    :param func: A callable that returns True on success.
    :param duration: The number of seconds for which to attempt a
        successful call of the function.
    :param sleep_for: The number of seconds to sleep after an unsuccessful
                      invocation of the function.
    :param args: args that are passed to func.
    :param kwargs: kwargs that are passed to func.
    """
    now = time.time()
    begin_time = now
    timeout = now + duration
    func_name = getattr(func, "__name__", getattr(func.__class__, "__name__"))
    while now < timeout:
        if func(*args, **kwargs):
            LOG.debug(
                "Call %s returns true in %f seconds",
                func_name,
                time.time() - begin_time,
            )
            return True
        time.sleep(sleep_for)
        now = time.time()
    LOG.debug("Call %s returns false in %f seconds", func_name, duration)
    return False
