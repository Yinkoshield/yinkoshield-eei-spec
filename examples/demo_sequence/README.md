# Demo: Ghost Transaction — Deterministic Retry Under Constrained Connectivity

## Scenario

In constrained-network environments, a payment flow can be partially executed: the request is sent, processed by the backend, but the response is lost in transit. The device has no confirmation and triggers a retry. The backend now sees two requests and must determine whether they represent one logical transaction or two.

Without execution evidence, the backend must infer from error codes and timeout patterns — a process that degrades under load and fails in edge cases.

This demo shows how `tctx` and `seq` resolve that ambiguity deterministically.

## Files

| File | Description |
|---|---|
| `01_minimal_profile.jws` | Attempt 1: `payment.initiated` · seq=1044 |
| `02_standard_profile.jws` | Attempt 1: `payment.initiated` (standard profile with extended fields) |
| `03_payment_retry.jws` | Attempt 2: `payment.retry` · seq=1045 · same `tctx` |
| `ledger_record_attempt1.json` | Full Evidence Record for attempt 1 (device-signed) |
| `ledger_record_attempt2.json` | Full Evidence Record for attempt 2 — `prev_hash` links to attempt 1 |

## What the backend observes

Both tokens carry `tctx = tctx-7c4e9a2f1b8d3e56`.

- Attempt 1: `event = payment.initiated`, `seq = 1044`
- Attempt 2: `event = payment.retry`, `seq = 1045`

`seq` is strictly monotonic within a boot session. A valid retry always has a higher `seq` than its predecessor. `tctx` is stable across both attempts — it was generated when the transaction was first initiated and never changes.

The backend correlates `tctx` and confirms `1045 > 1044`: this is a legitimate retry of the same logical transaction, not a duplicate charge.

## Verify yourself

```bash
# Verify attempt 1 (skip freshness — static fixture)
python verifiers/python/verifier.py \
  --token-file examples/demo_sequence/01_minimal_profile.jws \
  --pubkey keys/demo_public_key.pem \
  --skip-freshness

# Verify the retry
python verifiers/python/verifier.py \
  --token-file examples/demo_sequence/03_payment_retry.jws \
  --pubkey keys/demo_public_key.pem \
  --skip-freshness

# Verify the Evidence Record signature
python verifiers/python/verifier.py \
  --record examples/demo_sequence/ledger_record_attempt1.json \
  --pubkey keys/demo_public_key.pem
```
