from datetime import datetime, timezone

import pytest

import pico_acme


@pytest.mark.integration
def test_full_certificate_issuance_and_reissue(hosted_zone_id, test_domain):
    from pico_acme.route53 import route53_upsert_cleanup

    # 1. Register account on staging
    acme_client = pico_acme.register_account("test@pico-acme-test.a19e.net", agree_tos=True, staging=True)

    # 2. Generate ECDSA key and CSR
    key_pem = pico_acme.make_ecdsa_key()
    csr_pem = pico_acme.make_csr(key_pem, [test_domain])

    # 3. Issue certificate
    upsert_dns, cleanup_dns = route53_upsert_cleanup(hosted_zone_id)
    fullchain_pem = pico_acme.perform_dns01(acme_client, test_domain, csr_pem, upsert_dns, cleanup_dns)

    # 4. Verify returned PEM is a valid cert chain
    assert isinstance(fullchain_pem, str)
    assert "BEGIN CERTIFICATE" in fullchain_pem

    # 5. Check expiry is in the future
    expiry = pico_acme.get_expiry(fullchain_pem)
    assert isinstance(expiry, datetime)
    assert expiry > datetime.now(timezone.utc)

    # 6. Should not need renewal (just issued)
    assert pico_acme.should_renew(fullchain_pem) is False

    # 7. Serialize and deserialize the account
    data = pico_acme.serialize_account(acme_client)
    restored_client = pico_acme.deserialize_account(data, staging=True)
    assert restored_client.net.account.uri == acme_client.net.account.uri

    # 8. Reissue a cert with the restored client
    key_pem2 = pico_acme.make_ecdsa_key()
    csr_pem2 = pico_acme.make_csr(key_pem2, [test_domain])
    upsert_dns2, cleanup_dns2 = route53_upsert_cleanup(hosted_zone_id)
    fullchain_pem2 = pico_acme.perform_dns01(restored_client, test_domain, csr_pem2, upsert_dns2, cleanup_dns2)

    # 9. Verify second cert is valid
    assert "BEGIN CERTIFICATE" in fullchain_pem2
    assert pico_acme.get_expiry(fullchain_pem2) > datetime.now(timezone.utc)
