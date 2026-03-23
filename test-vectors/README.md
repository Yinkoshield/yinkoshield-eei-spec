# YinkoShield Evidence Token — Test Vectors

Comprehensive test vectors (23 total) covering all verification security categories and valid profiles.

## Overview

Test vectors validate that Evidence Token verifier implementations comply with SPEC.md § Verification, covering:

- **Valid tokens** (3) — Correct implementation paths
- **Invalid tokens** (20) — Security attacks and invalid states

All vectors are JWS-signed with the demo key pair in `../keys/`.

## Vector Structure

Each vector is a JSON object with:

```json
{
  "description": "What the vector tests",
  "token": "eyJ...",
  "kid": "yinkoshield.device.sign.v1",
  "expected": "VALID" or "REJECT",
  "attack": "Attack description (invalid vectors only)",
  "note": "Optional implementation notes"
}
```

For Evidence Record vectors (chain integrity tests), the object includes a `record` field instead of `token`.

## Valid Vectors (3)

### valid/minimal_profile.json
- **Scope**: Minimal token profile
- **Claims**: eid, did, kid, ts, seq, event, tctx, sig_ref only
- **Expected**: VALID
- **Test**: Basic verification path
- **Note**: Use `--skip-freshness` for static fixtures

### valid/standard_profile.json
- **Scope**: Extended profile with optional fields
- **Claims**: Includes schema_v, scope, boot_id, net
- **Expected**: VALID
- **Test**: Optional field handling
- **Note**: Use `--skip-freshness` for static fixtures

### valid/payment_retry.json
- **Scope**: Retry event with sequence tracking
- **Event**: payment.retry (one of the tracked retry events)
- **Expected**: VALID
- **Test**: Retry correlation flow

## Invalid Vectors by Category

### Signature Forged (4)

#### invalid/signature_forged/wrong_key.json
- **Attack**: Token signed with attacker's key but claims victim device kid
- **Detection**: Step 3 (signature verification fails)
- **Expected**: REJECT

#### invalid/signature_forged/corrupted_signature.json
- **Attack**: Signature bytes have been tampered
- **Detection**: Step 3 (signature verification fails)
- **Expected**: REJECT

#### invalid/signature_forged/empty_signature.json
- **Attack**: Signature segment is empty or invalid base64
- **Detection**: Step 3 (invalid signature length or decode failure)
- **Expected**: REJECT

#### invalid/signature_forged/unknown_kid.json
- **Attack**: Token claims a kid that is not registered
- **Detection**: Step 2 (kid lookup fails, refetch returns nil)
- **Expected**: REJECT

### Algorithm Confusion (2)

#### invalid/algorithm_confusion/hs256_claim.json
- **Attack**: Token header claims alg=HS256 (HMAC-SHA256, symmetric key)
- **Detection**: Step 1 (only ES256 is accepted)
- **Expected**: REJECT
- **Risk**: If verifier naively uses alg field to select signature algorithm, attacker could convince it to verify using HMAC with a known public key as the secret

#### invalid/algorithm_confusion/alg_none.json
- **Attack**: Token header claims alg=none (unsigned)
- **Detection**: Step 1 (only ES256 is accepted)
- **Expected**: REJECT
- **Risk**: If verifier accepts alg=none, signature verification is skipped

### Expired Token (2)

#### invalid/expired_token/one_hour_old.json
- **Attack**: Token is 60 minutes old
- **Detection**: Step 5 (age exceeds 5-minute freshness window by default)
- **Expected**: REJECT
- **Note**: Verifier must respect configurable freshness window (test with 2-hour window to confirm acceptance)

#### invalid/expired_token/future_dated.json
- **Attack**: Token is dated 60 minutes in the future
- **Detection**: Step 5 (age exceeds freshness window)
- **Expected**: REJECT

### Replay Attack (1)

#### invalid/replay_attack/duplicate_submission.json
- **Attack**: The same token is submitted twice
- **Detection**: Step 6 (deduplication: same did + tctx + event + seq seen before)
- **Expected**: REJECT on second submission (first is VALID)
- **Requirement**: Verifier must maintain dedup store across verification calls

### Missing Fields (8)

#### invalid/missing_fields/missing_eid.json
- **Attack**: Token lacks the eid field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_did.json
- **Attack**: Token lacks the did field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_kid.json
- **Attack**: Token lacks the kid header field
- **Detection**: Step 1 (kid required in header)
- **Expected**: REJECT

#### invalid/missing_fields/missing_ts.json
- **Attack**: Token lacks the ts field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_seq.json
- **Attack**: Token lacks the seq field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_event.json
- **Attack**: Token lacks the event field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_tctx.json
- **Attack**: Token lacks the tctx field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

#### invalid/missing_fields/missing_sig_ref.json
- **Attack**: Token lacks the sig_ref field
- **Detection**: Step 4 (required field missing)
- **Expected**: REJECT

### Sequence Regression (1)

#### invalid/sequence_regression/seq_lower_than_prior.json
- **Attack**: Retry event has seq ≤ prior attempt's seq
- **Detection**: Step 7 (retry correlation enforces seq > max_prior_seq)
- **Expected**: REJECT
- **Requirement**: Verifier must maintain flow store tracking (did, tctx) → [claims...]
- **Trigger Events**: payment.retry, pos.txn.retry, login.retry, auth.retry

### Broken Chain (2)

#### invalid/broken_chain/event_hash_mismatch.json
- **Attack**: Evidence Record's event_hash does not match computed hash of record content
- **Detection**: Record verification step (compute SHA256 of canonical record, compare to event_hash)
- **Expected**: REJECT
- **Test Scope**: Record chain verification (not token verification)

#### invalid/broken_chain/tampered_prev_hash.json
- **Attack**: Evidence Record's prev_hash does not link to prior record's event_hash
- **Detection**: Record chain verification (prev_hash != prior.event_hash)
- **Expected**: REJECT
- **Test Scope**: Record chain verification (not token verification)

## Using Test Vectors

### Manual Testing

Test a single vector:

```bash
python verifiers/python/verifier.py \
  --token-file test-vectors/valid/minimal_profile.json \
  --pubkey keys/demo_public_key.pem \
  --skip-freshness
# Expected output: VALID

python verifiers/python/verifier.py \
  --token-file test-vectors/invalid/signature_forged/wrong_key.json \
  --pubkey keys/demo_public_key.pem \
  --skip-freshness
# Expected output: REJECT
```

### Automated Test Suite

All language verifiers ship with complete test suites that validate against all test vectors:

- **Python**: `python -m pytest verifiers/python/tests/test_verifier.py -v`
- **JavaScript**: `node --test verifiers/javascript/tests/test_verifier.test.js`
- **Go**: `go test ./verifiers/go -v`

### Implementing a New Verifier

To validate a new verifier implementation:

1. Write a test harness that loads each vector
2. Call your verifier's verify() function with the token
3. Assert result.status == vector.expected
4. All 23 vectors must pass

Example (pseudocode):

```python
for vector_path in glob('test-vectors/**/*.json'):
    vector = load_json(vector_path)
    result = verifier.verify(vector['token'], skip_freshness=True)
    assert result.status == vector['expected'], \
        f"{vector_path}: expected {vector['expected']}, got {result.status}"
```

## Security Notes

These vectors test for:

- **Cryptographic failures** — Forged or invalid signatures
- **Algorithm attacks** — Confusion between signature algorithms
- **Timing attacks** — Freshness validation (test harness must use skip_freshness)
- **Replay attacks** — Stateful deduplication
- **State management** — Sequence regression in retry flows
- **Chain integrity** — Tampered or broken ledger chains

All vectors represent real attack scenarios a production verifier must defend against.

## Reference Implementation

See `../SPEC.md` (token verification order; **8-step** fail-closed pipeline) for the stages these vectors exercise:

1. Parse and validate JWS structure (including header for `alg` / `kid`)
2. Resolve signing key (`kid` in operator key store; optional re-fetch)
3. Verify ES256 signature
4. Parse and validate claims
5. Enforce freshness
6. Deduplicate `(did, tctx, event_name, seq)`
7. Correlate retries (sequence regression for normative retry events)
8. Resolve trust level (from linked Evidence Record when available, else `software_layer`)

## License

Copyright (c) 2025 Yinkozi Group — YinkoShield
