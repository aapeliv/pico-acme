import os

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as integration test (needs AWS creds + network)")


@pytest.fixture
def hosted_zone_id():
    zone_id = os.environ.get("ROUTE53_HOSTED_ZONE_ID")
    if not zone_id:
        pytest.skip("ROUTE53_HOSTED_ZONE_ID not set")
    return zone_id


@pytest.fixture
def test_domain():
    return "pico-acme-test.a19e.net"
