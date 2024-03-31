import json
from datetime import datetime, timedelta, timezone

import josepy as jose
import pyrfc3339
from acme import challenges, client, crypto_util, messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from OpenSSL import crypto

# let's encrypt ACMEv2 directory URLs
DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

USER_AGENT = "python-pico-acme"


def _get_directory_url(staging):
    if not staging:
        return DIRECTORY_URL
    else:
        return STAGING_DIRECTORY_URL


def register_account(account_email, *, agree_tos, staging=False):
    acc_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()))

    # Register account and accept TOS
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(_get_directory_url(staging), net)
    acme_client = client.ClientV2(directory, net=net)

    # Creates account with contact information.
    acme_client.new_account(
        messages.NewRegistration.from_data(email=(account_email), terms_of_service_agreed=agree_tos)
    )

    return acme_client


def serialize_account(acme_client):
    """
    Return the account data as JSON
    """
    return json.dumps({"acc_key": acme_client.net.key.to_json(), "regr": acme_client.net.account.to_json()})


def deserialize_account(data, staging=False):
    data = json.loads(data)
    acc_key = jose.JWK.from_json(data["acc_key"])

    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(_get_directory_url(staging), net)
    acme_client = client.ClientV2(directory, net=net)

    regr = acme_client.query_registration(messages.RegistrationResource.from_json(data["regr"]))

    return acme_client


def make_ecdsa_key(curve=ec.SECP256R1):
    """Generate PEM encoded EC key."""
    _key = ec.generate_private_key(curve=curve(), backend=default_backend())
    _key_pem = _key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()
    )
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, _key_pem)
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key)


def make_key() -> bytes:
    return make_ecdsa_key()


def make_csr(privkey_pem, domains, must_staple=False):
    return crypto_util.make_csr(privkey_pem, domains, must_staple=must_staple)


def select_dns01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                return i

    raise Exception("DNS-01 challenge was not offered by the CA server.")


def perform_dns01(acme_client, domain, csr_pem, upsert_dns, cleanup_dns):
    orderr = acme_client.new_order(csr_pem)
    challb = select_dns01_chall(orderr)
    record = challb.validation_domain_name(domain)
    response, challenge_value = challb.response_and_validation(acme_client.net.key)
    upsert_dns(record, challenge_value)
    acme_client.answer_challenge(challb, response)
    finalized_orderr = acme_client.poll_and_finalize(orderr)
    cleanup_dns(record, challenge_value)
    return finalized_orderr.fullchain_pem


def get_expiry(fullchain_pem):
    """
    Given a certificate, figures out the expiry date
    """
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain_pem.encode("ascii"))
    timestamp = crypto.X509.get_notAfter(x509)
    if not timestamp:
        raise Exception("Error while invoking timestamp method, None has been returned.")
    timestamp_bytes = b"".join(
        [
            timestamp[0:4],
            b"-",
            timestamp[4:6],
            b"-",
            timestamp[6:8],
            b"T",
            timestamp[8:10],
            b":",
            timestamp[10:12],
            b":",
            timestamp[12:],
        ]
    )
    return pyrfc3339.parse(timestamp_bytes.decode("ascii"))


def should_renew(fullchain_pem):
    return datetime.now(timezone.utc) > get_expiry(fullchain_pem) - timedelta(days=30)
