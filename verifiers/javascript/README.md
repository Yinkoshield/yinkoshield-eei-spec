# YinkoShield Evidence Token Verifier — JavaScript

A JavaScript reference implementation of the Evidence Token verification pipeline specified in SPEC.md.
Runs on Node.js 18+ with zero external dependencies (uses only the built-in `crypto` module).

## Installation

```bash
npm install
```

## Usage

### Verify a Token

Verify a token from a string (skip freshness check for static fixtures):

```bash
node verifier.js \
  --pubkey ../../keys/demo_public_key.pem \
  --token "eyJhbGciOiJFUzI1NiIsImtpZCI6Inlpbmtvc2hpZWxkLmRldmljZS5zaWduLnYxIn0..." \
  --skip-freshness
```

Or from a file:

```bash
node verifier.js \
  --pubkey ../../keys/demo_public_key.pem \
  --token-file ../../examples/demo_sequence/01_minimal_profile.jws \
  --skip-freshness
```

### Verify an Evidence Record

Verify a signed ledger record (Evidence Record):

```bash
node verifier.js \
  --pubkey ../../keys/demo_public_key.pem \
  --record ../../examples/full_evidence_record.json
```

## Programmatic Usage

```javascript
const { EvidenceTokenVerifier, KeyStore } = require('./verifier.js');

const keyStore = new KeyStore();
keyStore.loadPem('yinkoshield.device.sign.v1', 'path/to/public_key.pem');

const verifier = new EvidenceTokenVerifier(keyStore);
const result = verifier.verify(tokenString, { skipFreshness: false });

if (result.ok) {
  console.log(`✓ Token valid`);
  console.log(`  Event: ${result.claims.event}`);
  console.log(`  Device: ${result.claims.did}`);
  console.log(`  Trust: ${result.trustLevel}`);
} else {
  console.log(`✗ Verification failed: ${result.reason}`);
}
```

## Testing

Run the full test suite:

```bash
npm test
```

Or manually:

```bash
node --test tests/test_verifier.test.js
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
