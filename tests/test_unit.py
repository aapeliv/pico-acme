from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL import crypto

import pico_acme


def test_make_key():
    key_pem = pico_acme.make_key()
    assert isinstance(key_pem, bytes)
    assert b"BEGIN" in key_pem and b"PRIVATE KEY" in key_pem
    # Loadable as a valid private key
    key = load_pem_private_key(key_pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)


def test_make_ecdsa_key_default():
    key_pem = pico_acme.make_ecdsa_key()
    assert isinstance(key_pem, bytes)
    key = load_pem_private_key(key_pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)


def test_make_ecdsa_key_custom_curve():
    key_pem = pico_acme.make_ecdsa_key(curve=ec.SECP384R1)
    assert isinstance(key_pem, bytes)
    key = load_pem_private_key(key_pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP384R1)


def _load_csr(csr_bytes):
    """Load CSR from bytes, trying PEM then DER."""
    try:
        return cx509.load_pem_x509_csr(csr_bytes)
    except ValueError:
        return cx509.load_der_x509_csr(csr_bytes)


def test_make_csr():
    key_pem = pico_acme.make_key()
    domains = ["example.com", "www.example.com"]
    csr_bytes = pico_acme.make_csr(key_pem, domains)
    assert isinstance(csr_bytes, bytes)
    csr = _load_csr(csr_bytes)
    san = csr.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    csr_domains = san.value.get_values_for_type(cx509.DNSName)
    assert set(csr_domains) == set(domains)


def test_make_csr_must_staple():
    key_pem = pico_acme.make_key()
    csr_bytes = pico_acme.make_csr(key_pem, ["example.com"], must_staple=True)
    csr = _load_csr(csr_bytes)
    # OCSP Must-Staple is TLS Feature extension OID 1.3.6.1.5.5.7.1.24
    tls_feature_oid = cx509.ObjectIdentifier("1.3.6.1.5.5.7.1.24")
    found = any(ext.oid == tls_feature_oid for ext in csr.extensions)
    assert found, "CSR should contain TLS Feature (OCSP Must-Staple) extension"


def test_get_expiry():
    # Create a self-signed cert with known expiry
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 3600)  # 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("ascii")

    expiry = pico_acme.get_expiry(pem)
    assert isinstance(expiry, datetime)
    assert expiry.tzinfo is not None
    # Should be roughly 1 year from now
    assert expiry > datetime.now(timezone.utc) + timedelta(days=360)
    assert expiry < datetime.now(timezone.utc) + timedelta(days=370)


def test_should_renew_expired():
    # Create an already-expired cert
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(-7200)
    cert.gmtime_adj_notAfter(-3600)  # expired 1 hour ago
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("ascii")

    assert pico_acme.should_renew(pem) is True


def test_should_renew_not_yet():
    # Create cert expiring in 90 days (well outside 30-day window)
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(90 * 24 * 3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("ascii")

    assert pico_acme.should_renew(pem) is False


def test_serialize_deserialize_roundtrip():
    acme_client = pico_acme.register_account("test@pico-acme-test.a19e.net", agree_tos=True, staging=True)
    data = pico_acme.serialize_account(acme_client)
    assert isinstance(data, str)

    restored = pico_acme.deserialize_account(data, staging=True)
    # Verify the restored client has the same account URI
    assert restored.net.account.uri == acme_client.net.account.uri


def test_version():
    version_file = Path(__file__).parent.parent / "src" / "pico_acme" / "version"
    expected = version_file.read_text().strip()
    assert pico_acme.__version__ == expected
