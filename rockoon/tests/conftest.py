import pytest
import datetime


@pytest.fixture(scope="function", autouse=True)
def save_test_time_property(record_property):
    record_property(
        "start_time", datetime.datetime.now(datetime.UTC).isoformat()
    )
    yield
    record_property(
        "end_time", datetime.datetime.now(datetime.UTC).isoformat()
    )
