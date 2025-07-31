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

import base64
import pytest

from rockoon import utils
from rockoon import exception


def test_divide_into_groups_of():
    assert [["a", "b", "c"]] == utils.divide_into_groups_of(3, ["a", "b", "c"])
    assert [["a", "b"], ["c", "d"], ["e"]] == utils.divide_into_groups_of(
        2, ["a", "b", "c", "d", "e"]
    )
    assert [] == utils.divide_into_groups_of(2, [])
    assert [["a"]] == utils.divide_into_groups_of(5, ["a"])


def test_cron_validator():
    samples = [
        ["* * * * *", True],
        ["* 9* * * *", False],
        ["00 * * * *", True],
        ["59 * * * *", True],
        ["62 * * * *", False],
        ["* 00 * * *", True],
        ["* 23 * * *", True],
        ["* 30 * * *", False],
        ["* * 00 * *", False],
        ["* * 01 * *", True],
        ["* * 31 * *", True],
        ["* * 33 * *", False],
        ["* * * 00 *", False],
        ["* * * 01 *", True],
        ["* * * 12 *", True],
        ["* * * 15 *", False],
        ["* * * juN *", True],
        ["* * * ser * ", False],
        ["* * * * 00", True],
        ["* * * * 07", True],
        ["* * * * 09", False],
        ["* * * * mon", True],
        ["* * * * vos", False],
        ["*/5 * * * *", True],
        ["* */3/5 * * *", False],
        ["*/1-5 * * * *", False],
        ["1/5 * * * *", False],
        ["1-40/5 * * * *", True],
        ["1-4/* * * * *", False],
        ["1,3,6 * * * *", True],
        ["* * * 1,5,jan,7 *", False],
        ["40-5 * * * *", False],
        ["0-62 * * * *", False],
        ["5-12 * * * *", True],
        ["1-1 * * * *", True],
        ["* * * 02-07,9 *", True],
        ["* * * * 0-5-6", False],
        ["* * * * 1,7,6", True],
        ["*/5 1,18 * 2-4 7", True],
        ["* */3 * * Mon ", True],
        ["02 06 05 01 01", True],
        ["22 06 15 17 *", False],
        ["1-20/3 * * Jan *", True],
        ["* * * Jan,may *", False],
        ["* * * mar-sep *", False],
        ["15- 0 0 0 0", False],
        ["/ 0 0 0 0", False],
        ["1-3 * * */jan *", False],
        ["@weekly", True],
        ["@yearly", True],
        ["* */20,7,*/12 * * *", True],
        ["* * * 1-14 *", False],
        ["* * * ", False],
        ["* * * * * *", False],
    ]
    for schedule, res in samples:
        assert utils.CronValidator(schedule).validate() == res


def test_find_and_substitute_ok():
    secrets = {
        "mysecret": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
        "mysecret2": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
    }
    in_data = {
        "spec": {
            "features": {
                "ssl": {
                    "api_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "name": "mysecret",
                                "key": "opt1",
                            }
                        }
                    }
                }
            },
            "s3": {
                "value_from": {
                    "secret_key_ref": {"name": "mysecret2", "key": "opt2"}
                }
            },
        }
    }

    expected = {
        "spec": {"features": {"ssl": {"api_key": "sval1"}}, "s3": "sval2"}
    }
    res = utils.find_and_substitute(in_data, secrets)
    assert res == expected


def test_find_and_substitute_secret_not_found():
    secrets = {
        "mysecret": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
        "mysecret2": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
    }
    in_data = {
        "spec": {
            "features": {
                "ssl": {
                    "api_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "name": "mysecret",
                                "key": "opt1",
                            }
                        }
                    }
                }
            },
            "s3": {
                "value_from": {
                    "secret_key_ref": {"name": "mysecret3", "key": "opt2"}
                }
            },
        }
    }

    with pytest.raises(exception.OsdplSubstitutionFailed) as e:
        utils.find_and_substitute(in_data, secrets)
        assert "Specified secret mysecret3 not found" in e.message


def test_find_and_substitute_key_not_found():
    secrets = {
        "mysecret": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
        "mysecret2": {
            "opt1": base64.encodebytes("sval1".encode("ascii")).decode(
                "ascii"
            ),
            "opt2": base64.encodebytes("sval2".encode("ascii")).decode(
                "ascii"
            ),
        },
    }
    in_data = {
        "spec": {
            "features": {
                "ssl": {
                    "api_key": {
                        "value_from": {
                            "secret_key_ref": {
                                "name": "mysecret",
                                "key": "opt1",
                            }
                        }
                    }
                }
            },
            "s3": {
                "value_from": {
                    "secret_key_ref": {"name": "mysecret2", "key": "opt3"}
                }
            },
        }
    }

    with pytest.raises(exception.OsdplSubstitutionFailed) as e:
        utils.find_and_substitute(in_data, secrets)
        assert "Specified key opt3 not found in mysecret2" in e.message


def test_merge_lists_appends_new():
    """When merging lists, we append new uniq elements"""
    d1 = {"list": [1, 2, 3]}
    d2 = {"list": [4, 3, 2]}
    assert utils.merger.merge(d1, d2) == {"list": [1, 2, 3, 4]}


def test_merge_lists_remove():
    """When merging lists, we can remove elements starts with '~'"""
    d1 = {"list": ["foo", "bar", "baz"]}
    d2 = {"list": ["~bar"]}
    assert utils.merger.merge(d1, d2) == {"list": ["foo", "baz"]}


def test_merge_allows_float_over_int():
    """We allow overwriting ints with floats"""
    d1 = {"value": 1}
    d2 = {"value": 1.1}
    assert utils.merger.merge(d1, d2) == {"value": 1.1}


def test_merge_allows_int_over_float():
    """We allow overwriting floats with ints"""
    d1 = {"value": 1.1}
    d2 = {"value": 1}
    assert utils.merger.merge(d1, d2) == {"value": 1}


def test_merge_allows_none():
    """We allow overwriting none with any value"""
    d1 = {"value": 1.1, "value2": None}
    d2 = {"value2": 2}
    assert utils.merger.merge(d1, d2) == {"value": 1.1, "value2": 2}


def test_merge_allows_none_deep():
    """We allow overwriting none with any value"""
    d1 = {"value": 1.1, "value2": None}
    d2 = {"value2": {"foo": "bar"}}
    assert utils.merger.merge(d1, d2) == {
        "value": 1.1,
        "value2": {"foo": "bar"},
    }
