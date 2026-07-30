

# pico acme

El paquete de Python más pequeño para obtener certificados ACMEv2 de [Let's Encrypt](https://letsencrypt.org/).

Solo admite dominios individuales y el desafío DNS. Actualmente implementa AWS Route 53, pero puedes implementar fácilmente tu propio proveedor.

Licenciado bajo Apache 2.0, ya que reutiliza parte del código de certbot.

## inicio rápido

Instalación desde PyPI:

```sh
pip install pico-acme
```

(Ten en cuenta que necesitas instalar `boto3` por separado para usar `route53`.)

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

### verificar si necesitas renovar

```py
import pico_acme

with open("fullchain.pem") as f:
    fullchain_pem = f.read()

if pico_acme.should_renew(fullchain_pem):
    print("due for renewal")
```

## arquitectura y características

La función `perform_dns01` recibe dos funciones llamables: `upsert(record, value)`, que debe establecer el valor `value` (la cadena de verificación) en el registro `record` (por ejemplo, `_acme-challenge.example.com`), y `clean(record, value)`, que debe limpiar estos registros. Consulta la implementación en `route53.py` para más detalles.

## agradecimientos

Este proyecto se basa muy fuertemente en [certbot](https://github.com/certbot/certbot), con porciones de código copiadas directamente.
