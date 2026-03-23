# YinkoShield Evidence Token Verifier — Python

A Python reference implementation of the Evidence Token verification pipeline specified in SPEC.md.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Verify a Token

Verify a token from a string (skip freshness check for static fixtures):

```bash
python verifier.py \
  --token "eyJhbGciOiJFUzI1NiIsImtpZCI6Inlpbmtvc2hpZWxkLmRldmljZS5zaWduLnYxIn0..." \
  --pubkey ../../keys/demo_public_key.pem \
  --skip-freshness
```

Or from a file:

```bash
python verifier.py \
  --token-file ../../examples/demo_sequence/01_minimal_profile.jws \
  --pubkey ../../keys/demo_public_key.pem \
  --skip-freshness
```

### Verify an Evidence Record

Verify a signed ledger record (Evidence Record):

```bash
python verifier.py \
  --record ../../examples/full_evidence_record.json \
  --pubkey ../../keys/demo_public_key.pem
```

## Programmatic Usage

```python
from verifier import EvidenceTokenVerifier, KeyStore

store = KeyStore()
store.load_pem("yinkoshield.device.sign.v1", "path/to/public_key.pem")

verifier = EvidenceTokenVerifier(store)
result = verifier.verify(token_string, skip_freshness=False)

if result:
    print(f"✓ Token valid")
    print(f"  Event: {result.claims['event']}")
    print(f"  Device: {result.claims['did']}")
    print(f"  Trust: {result.trust_level.value}")
else:
    print(f"✗ Verification failed: {result.reason}")
```

## Testing

Run the full test suite:

```bash
cd verifiers/python
pytest tests/test_verifier.py -v
```

This runs all 34 tests including:

- Valid token verification (minimal and standard profiles)
- Signature validation (forged, algorithm confusion)
- Freshness enforcement
- Replay detection (deduplication)
- Retry correlation and sequence regression
- Chain integrity verification
- Trust level evaluation

## Implementation Details

The verifier implements the **8-step** pipeline defined in `SPEC.md` (fail-closed):

1. **Parse JWS** — Structure, base64url, header `alg` / `kid`; production size and header allowlist where applicable
2. **Resolve signing key** — Look up device public key by `kid`; optional authenticated re-fetch
3. **Verify signature** — ES256 over `header_b64.payload_b64`
4. **Parse and validate claims** — Required fields, types, UUIDs, `kid` match, production string/integer limits
5. **Enforce freshness** — Reject outside configured window (default ±5 minutes; configurable)
6. **Deduplicate** — Reject replay on `(did, tctx, event_name, seq)`
7. **Correlate retries** — Sequence regression for normative retry `event_name` values
8. **Trust level** — From linked Evidence Record when available; else `software_layer`

## License

Copyright (c) 2025 Yinkozi Group — YinkoShield
