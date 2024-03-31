# pico acme

The tiniest python package to get ACMEv2 certs from [Let's Encrypt](https://letsencrypt.org/).

Supports only single domains and DNS challenge. Currently implements AWS Route 53 but you can trivially implement your own provider.

Licensed under Apache 2.0 as this reuses some code from certbot.

## quick start

Install from PyPI:

```sh
pip install pico-acme
```

(Note that you need to install `boto3` separately to use `route53`.)

### `new.py`:

```py
ROUTE53_HOSTED_ZONE_ID = "..."
ACCOUNT_EMAIL = "domains@example.com"
DOMAIN = "example.com"

# create account, get cert, and save details
import pico_acme
from pico_acme import route53

# register an acme account
acme_client = pico_acme.register_account(ACCOUNT_EMAIL, agree_tos=True)

# create a private key and certificate signing request
key_pem = pico_acme.make_key()
csr_pem = pico_acme.make_csr(key_pem, [DOMAIN])

# get functions for upserting and cleaning up DNS records in AWS Route 53
upsert, clean = route53.route53_upsert_cleanup(ROUTE53_HOSTED_ZONE_ID)

# perform DNS-01 challenge to get the full chain as PEM
fullchain_pem = pico_acme.perform_dns01(acme_client, DOMAIN, csr_pem, upsert, clean)

# save account for later
with open("pico_acme_account.json", "w") as f:
    f.write(pico_acme.serialize_account(acme_client))

# save private key for later
with open("key.pem", "wb") as f:
    f.write(key_pem)

# save the cert for later
with open("fullchain.pem", "w") as f:
    f.write(fullchain_pem)
```

### `renew.py`:

```py
ROUTE53_HOSTED_ZONE_ID = "..."
DOMAIN = "example.com"

# later, load account, private key, and renew cert
import pico_acme
from pico_acme import route53

# load account
with open("pico_acme_account.json") as f:
    acme_client = pico_acme.deserialize_account(f.read())

# load private key
with open("key.pem", "rb") as f:
    key_pem = f.read()

# make a new certificate signing request
csr_pem = pico_acme.make_csr(key_pem, [DOMAIN])

# get functions for upserting and cleaning up DNS records in AWS Route 53
upsert, clean = route53.route53_upsert_cleanup(ROUTE53_HOSTED_ZONE_ID)

# perform DNS-01 challenge to get the full chain as PEM
fullchain_pem = pico_acme.perform_dns01(acme_client, DOMAIN, csr_pem, upsert, clean)

# save the cert for later
with open("fullchain.pem", "w") as f:
    f.write(fullchain_pem)
```

### checking if you need to renew

```py
import pico_acme

with open("fullchain.pem") as f:
    fullchain_pem = f.read()

if pico_acme.should_renew(fullchain_pem):
    print("due for renewal")
```

## architecture & features

The `perform_dns01` takes two callables, `upsert(record, value)` which should set the value `value` (the verification string) in record `record` (e.g. `_acme-challenge.example.com`), and `clean(record, value)` which should clean these up. See the `route53.py` implementation for details.

## acknowledgements

This is based very heavily on [certbot](https://github.com/certbot/certbot), with portions copied directly.
