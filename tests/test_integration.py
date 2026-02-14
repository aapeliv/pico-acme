from datetime import datetime, timezone

import pytest

import pico_acme
from pico_acme.route53 import route53_upsert_cleanup


@pytest.mark.integration
def test_full_certificate_issuance(hosted_zone_id, test_domain):
    # 1. Register account on staging
    acme_client = pico_acme.register_account("test@pico-acme-test.a19e.net", agree_tos=True, staging=True)

    # 2. Generate ECDSA key
    key_pem = pico_acme.make_ecdsa_key()

    # 3. Create CSR
    csr_pem = pico_acme.make_csr(key_pem, [test_domain])

    # 4. Get DNS callbacks
    upsert_dns, cleanup_dns = route53_upsert_cleanup(hosted_zone_id)

    # 5. Issue certificate
    fullchain_pem = pico_acme.perform_dns01(acme_client, test_domain, csr_pem, upsert_dns, cleanup_dns)

    # 6. Verify returned PEM is a valid cert chain
    assert isinstance(fullchain_pem, str)
    assert "BEGIN CERTIFICATE" in fullchain_pem

    # 7. Check expiry is in the future
    expiry = pico_acme.get_expiry(fullchain_pem)
    assert isinstance(expiry, datetime)
    assert expiry > datetime.now(timezone.utc)

    # 8. Should not need renewal (just issued)
    assert pico_acme.should_renew(fullchain_pem) is False


@pytest.mark.integration
def test_serialize_deserialize_and_reissue(hosted_zone_id, test_domain):
    # 1. Register account on staging
    acme_client = pico_acme.register_account("test@pico-acme-test.a19e.net", agree_tos=True, staging=True)

    # 2. Serialize and deserialize
    data = pico_acme.serialize_account(acme_client)
    restored_client = pico_acme.deserialize_account(data, staging=True)

    # 3. Issue a cert with the deserialized client
    key_pem = pico_acme.make_ecdsa_key()
    csr_pem = pico_acme.make_csr(key_pem, [test_domain])
    upsert_dns, cleanup_dns = route53_upsert_cleanup(hosted_zone_id)
    fullchain_pem = pico_acme.perform_dns01(restored_client, test_domain, csr_pem, upsert_dns, cleanup_dns)

    # 4. Verify cert is valid
    assert isinstance(fullchain_pem, str)
    assert "BEGIN CERTIFICATE" in fullchain_pem
    expiry = pico_acme.get_expiry(fullchain_pem)
    assert expiry > datetime.now(timezone.utc)
