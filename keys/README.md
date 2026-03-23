# Demo Keys

These keys are for **demonstration and testing only**. They are published intentionally so developers can verify the example tokens and records in this repository.

**Never use these keys in production. Never treat them as secret.**

## Files

| File | Description |
|---|---|
| `demo_private_key.pem` | EC P-256 private key — used to generate signed examples |
| `demo_public_key.pem` | EC P-256 public key — use this to verify all examples |
| `demo_public_key.jwk.json` | Same public key in JWK format |

## Key identifier

All signed examples in this repository use:

```
kid: yinkoshield.device.sign.v1
```

## Verify a token yourself

```python
# Python
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64, json

with open('demo_public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

token = open('../examples/demo_sequence/01_minimal_profile.jws').read().strip()
header_b64, payload_b64, sig_b64 = token.split('.')

def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

signing_input = f"{header_b64}.{payload_b64}".encode()
raw_sig = b64url_decode(sig_b64)
r = int.from_bytes(raw_sig[:32], 'big')
s = int.from_bytes(raw_sig[32:], 'big')
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
der_sig = encode_dss_signature(r, s)
public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
print("Signature valid!")
```

Or use the verifier: `cd ../verifiers/python && python verifier.py`
