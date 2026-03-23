# Demo: Chargeback Defence via Device-Signed Execution Provenance

## Scenario

A cardholder disputes a transaction: *"I never initiated this payment."*

Today the issuer presents backend logs and a risk score. Neither proves what happened on the device. The dispute becomes a credibility contest, and schemes absorb the cost of ambiguity.

This demo shows how device-signed execution provenance resolves the dispute deterministically.

## Files

| File | Description |
|---|---|
| `ledger_record_auth.json` | Biometric auth event · seq=1043 · `auth.biometric.confirmed` |
| `ledger_record_payment.json` | Payment event · seq=1044 · `payment.initiated` · `prev_hash` links to seq=1043 |

## What the issuer presents

1. **Auth record** (seq=1043, ts=T+0s): `auth.biometric.confirmed` — the user authenticated biometrically on the device 13 seconds before the payment.
2. **Payment record** (seq=1044, ts=T+13s): `payment.initiated` — the payment followed immediately.
3. **Chain linkage**: `ledger_record_payment.json → chain_ref.prev_hash` matches `ledger_record_auth.json → chain_ref.event_hash`. The two records are cryptographically linked.
4. **Signatures**: both records carry `sig.value` signed with `kid: yinkoshield.device.sign.v1`. Verify against the registered device public key.

The chargeback claim is not credible against this evidence.

## Verify the chain yourself

```bash
# Verify auth record signature
python verifiers/python/verifier.py \
  --record examples/chargeback_dispute/ledger_record_auth.json \
  --pubkey keys/demo_public_key.pem

# Verify payment record signature
python verifiers/python/verifier.py \
  --record examples/chargeback_dispute/ledger_record_payment.json \
  --pubkey keys/demo_public_key.pem

# Run the full chain integrity test
python -m pytest verifiers/python/tests/test_verifier.py::TestChainIntegrity::test_auth_payment_chain -v
```

## Hash chain verification (manual)

The `chain_ref.prev_hash` in `ledger_record_payment.json` should equal the `chain_ref.event_hash` in `ledger_record_auth.json`. You can verify this directly:

```python
import json, hashlib

with open("examples/chargeback_dispute/ledger_record_auth.json") as f:
    auth = json.load(f)
with open("examples/chargeback_dispute/ledger_record_payment.json") as f:
    pay = json.load(f)

auth_hash = auth["chain_ref"]["event_hash"]
pay_prev  = pay["chain_ref"]["prev_hash"]

print("Auth event_hash:   ", auth_hash[:32] + "...")
print("Payment prev_hash: ", pay_prev[:32] + "...")
print("Chain intact:", auth_hash == pay_prev)
```
