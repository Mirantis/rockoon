#    Copyright 2020 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import asyncio
import base64
import copy
import datetime
import difflib
import functools
import logging
import logging.config
import os
import re
import requests
import hashlib
import time
from typing import Dict, List
import yaml

import deepmerge
import deepmerge.exception
from deepmerge.strategy import dict as merge_dict
from deepmerge.strategy import list as merge_list
import deepmerge.strategy.type_conflict
from urllib.parse import urlsplit

from rockoon import exception


def get_in(d: Dict, keys: List, default=None):
    """Returns the value in a nested dict, where keys is a list of keys.

    >>> get_in({"a": {"b": 1}}, ["a", "b"])
    1
    >>> get_in({"a": [0, 1, 2]}, ["a", 1])
    1
    >>> get_in({"a": {"b": 1}}, ["a", "x"], "not found")
    'not found'

    """
    if not keys:
        return d
    try:
        return get_in(d[keys[0]], keys[1:], default)
    except (KeyError, IndexError):
        return default


OSCTL_LOGGING_CONF_FILE = os.environ.get(
    "OSCTL_LOGGING_CONF_FILE", "/etc/rockoon/logging.conf"
)


def get_logger(name: str) -> logging.Logger:
    with open(OSCTL_LOGGING_CONF_FILE, "r") as f:
        logging_conf = yaml.safe_load(f)
        logging.config.dictConfig(logging_conf)

    logger = logging.getLogger(name)
    return logger


LOG = get_logger(__name__)


def k8s_timestamp_to_unix(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()


def to_base64(value: str) -> str:
    return base64.encodebytes(value.encode("ascii")).decode("ascii")


def from_base64(value: str) -> str:
    return base64.decodebytes(value.encode("ascii")).decode("ascii")


def divide_into_groups_of(group_len, collection):
    groups = []
    for i in range(len(collection) // group_len):
        groups.append(collection[i * group_len : i * group_len + group_len])
    if len(collection) % group_len:
        groups.append(collection[-(len(collection) % group_len) :])
    return groups


async def async_retry(function, *args, **kwargs):
    result = None
    while not result:
        result = function(*args, **kwargs)
        if result:
            return result
        await asyncio.sleep(10)


def get_topic_normalized_name(name):
    if bool(re.match(r"^[a-z0-9-.]*$", name)):
        return name
    else:
        name = name.lower()
        hash_suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:5]
        name = re.sub("[^a-z0-9-.]", "", name)
        name = "-".join([name, hash_suffix])
        return name


class TypeConflictFail(
    deepmerge.strategy.type_conflict.TypeConflictStrategies
):
    @staticmethod
    def strategy_fail(config, path, base, nxt):
        if type(base) in (float, int) and type(nxt) in (float, int):
            return nxt
        raise deepmerge.exception.InvalidMerge(
            f"Trying to merge different types of objects, {type(base)} and "
            f"{type(nxt)} at path {':'.join(path)}",
            config,
            path,
            base,
            nxt,
        )


class CustomListStrategies(merge_list.ListStrategies):
    """
    Contains the strategies provided for lists.
    """

    def strategy_merge(config, path, base, nxt):
        """Merge base with nxt, adds new elements from nxt.

        If element is string and start with ~ remove element from list.
        """
        merged = copy.deepcopy(base)
        for el in nxt:
            if isinstance(el, str) and el.startswith("~"):
                try:
                    merged.remove(el[1:])
                except ValueError:
                    pass
            elif el not in merged:
                merged.append(el)
        return merged


class CustomMerger(deepmerge.Merger):
    PROVIDED_TYPE_STRATEGIES = {
        list: CustomListStrategies,
        dict: merge_dict.DictStrategies,
    }

    def __init__(
        self, type_strategies, fallback_strategies, type_conflict_strategies
    ):
        super(CustomMerger, self).__init__(
            type_strategies, fallback_strategies, []
        )
        self._type_conflict_strategy_with_fail = TypeConflictFail(
            type_conflict_strategies
        )

    def type_conflict_strategy(self, *args):
        return self._type_conflict_strategy_with_fail(self, *args)


merger = CustomMerger(
    # pass in a list of tuple, with the strategies you are looking to apply
    # to each type.
    # NOTE(pas-ha) We are handling results of yaml.safe_load and k8s api
    # exclusively, thus only standard json-compatible collection data types
    # will be present, so not botherting with collections.abc for now.
    [(list, ["merge"]), (dict, ["merge"])],
    # next, choose the fallback strategies, applied to all other types:
    ["override"],
    # finally, choose the strategies in the case where the types conflict:
    ["fail"],
)


def substitute_local_proxy_hostname(url, hostname):
    """Point artifact to use nodeIP instead of 127.0.0.1"""
    parsed = urlsplit(url)
    if not parsed.hostname == "127.0.0.1":
        return url
    new_netloc = hostname
    auth = parsed.username
    new_netloc = hostname
    if auth:
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        new_netloc = f"{auth}@{new_netloc}"
    if parsed.port:
        new_netloc = f"{new_netloc}:{parsed.port}"
    return parsed._replace(netloc=new_netloc).geturl()


class cronScheduleNotValid(Exception):
    """Class for cron validator exceptions"""


class CronValidatorBase:
    min = None
    max = None

    def __init__(self, expression):
        self.expression = expression

    def _check_item(self, element):
        if element.isdigit():
            return int(element) >= self.min and int(element) <= self.max
        elif element == "*":
            return True
        else:
            return False

    def _check_range(self, element):
        parts = element.split("-")
        if len(parts) == 2:
            if parts[0].isdigit() and parts[1].isdigit():
                if self._check_item(parts[0]) and self._check_item(parts[1]):
                    return int(parts[0]) <= int(parts[1])
        return False

    def _check_step(self, element):
        parts = element.split("/")
        if len(parts) == 2:
            if parts[1].isdigit():
                if self._check_item(parts[1]):
                    if "-" in parts[0]:
                        return self._check_range(parts[0])
                    elif parts[0] == "*":
                        return True
        return False

    def _check_list(self, element):
        parts = element.split(",")
        for item in parts:
            if "/" in item:
                result = self._check_step(item)
            elif "-" in item:
                result = self._check_range(item)
            else:
                result = self._check_item(item)
            if not result:
                break
        return result

    def validate(self):
        if not self._check_list(self.expression):
            raise cronScheduleNotValid()


class CronValidateMinutes(CronValidatorBase):
    min = 0
    max = 59


class CronValidateHours(CronValidatorBase):
    min = 0
    max = 23


class CronValidateDays(CronValidatorBase):
    min = 1
    max = 31


class CronValidateMonths(CronValidatorBase):
    min = 1
    max = 12
    names = [
        "jan",
        "feb",
        "mar",
        "apr",
        "may",
        "jun",
        "jul",
        "aug",
        "sep",
        "oct",
        "nov",
        "dec",
    ]

    def _check_item(self, element):
        if element in self.names:
            return True
        else:
            return super()._check_item(element)

    def _check_list(self, element):
        parts = element.split(",")
        if len(parts) > 1 and len(set(parts) & set(self.names)) != 0:
            return False
        return super()._check_list(element)


class CronValidateDaysOfWeek(CronValidateMonths):
    min = 0
    max = 7
    names = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]


class CronValidator:
    nicknames = [
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@hourly",
    ]

    def __init__(self, schedule):
        self.schedule = schedule.strip().lower()

    def _is_nickname(self):
        return self.schedule in self.nicknames

    def validate(self):
        if self._is_nickname():
            return True
        blocks = self.schedule.split(" ")
        try:
            minutes, hours, days, month, dow = blocks
            CronValidateMinutes(minutes).validate()
            CronValidateHours(hours).validate()
            CronValidateDays(days).validate()
            CronValidateMonths(month).validate()
            CronValidateDaysOfWeek(dow).validate()
        except (TypeError, ValueError, cronScheduleNotValid):
            return False
        return True


def find_and_substitute(obj, secrets):
    if not isinstance(obj, dict):
        return obj
    for k, v in obj.items():
        if isinstance(v, dict) and "value_from" in v:
            if "secret_key_ref" in v["value_from"]:
                obj[k] = substitute_hidden_field(v["value_from"], secrets)
        # do not allow double substitution
        else:
            find_and_substitute(v, secrets)
    return obj


def substitute_hidden_field(ref, secrets):
    if "secret_key_ref" in ref:
        ref = ref["secret_key_ref"]
        secret_name = ref["name"]
        secret_key = ref["key"]
        if secret_name not in secrets:
            raise exception.OsdplSubstitutionFailed(
                f"Specified secret {secret_name} not found."
            )
        data = secrets[secret_name].get(secret_key)
        if data is None:
            raise exception.OsdplSubstitutionFailed(
                f"Specified key {secret_key} not found in secret {secret_name}."
            )
        return from_base64(data)


def download_file(url, dst, timeout=60, chunk_size=8192):
    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        with open(dst, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                f.write(chunk)
    return dst


def timeit(f):
    def timed(*args, **kw):
        start = time.time()
        result = f(*args, **kw)
        end = time.time()
        LOG.debug("%s took: %2.4f sec" % (f.__qualname__, end - start))
        return result

    return timed


def log_exception_and_raise(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise

    return wrapper


def log_changes(old, new):
    old = old or {}
    new = new or {}
    old_yaml = yaml.dump(old, sort_keys=True)
    new_yaml = yaml.dump(new, sort_keys=True)
    diff = "\n" + "\n".join(
        difflib.unified_diff(
            old_yaml.splitlines(),
            new_yaml.splitlines(),
        )
    )
    LOG.info("Changes are: %s", diff)
