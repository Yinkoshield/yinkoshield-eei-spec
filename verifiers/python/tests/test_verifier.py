# Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
#
# YinkoShield Execution Evidence Infrastructure
# Evidence Token Verifier — Python Test Suite
#
# This is a reference implementation of the verification pipeline defined in SPEC.md.
# It demonstrates sovereign verification: no YinkoShield infrastructure required.
# Verification uses only the registered device public key.
#
# https://github.com/yinkoshield
"""
YinkoShield Evidence Token Verifier — Test Suite

Tests all security test vectors and behavioral requirements for:
- Valid token verification (minimal and standard profiles)
- Replay detection
- Retry correlation and sequence enforcement
- Chain integrity
- Trust level evaluation

Usage:
    cd verifiers/python
    pip install cryptography pytest
    pytest tests/test_verifier.py -v
"""

import base64
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verifier import (  # noqa: E402
    EvidenceTokenVerifier,
    EvidenceRecordVerifier,
    KeyStore,
    VerificationResult,
    VerificationStatus,
    TrustLevel,
    evaluate_trust,
    verify_token_record_binding,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
KEYS_DIR = os.path.join(REPO_ROOT, "keys")
VECTORS_DIR = os.path.join(REPO_ROOT, "test-vectors")
EXAMPLES_DIR = os.path.join(REPO_ROOT, "examples")
DEMO_KID = "yinkoshield.device.sign.v1"


@pytest.fixture
def key_store():
    store = KeyStore()
    store.load_pem(DEMO_KID, os.path.join(KEYS_DIR, "demo_public_key.pem"))
    return store


@pytest.fixture
def verifier(key_store):
    return EvidenceTokenVerifier(key_store)


@pytest.fixture
def record_verifier(key_store):
    return EvidenceRecordVerifier(key_store)


def load_vector(path):
    with open(os.path.join(VECTORS_DIR, path)) as f:
        return json.load(f)


def load_record(path):
    with open(os.path.join(EXAMPLES_DIR, path)) as f:
        return json.load(f)


# ── Token-signing utility (for crafted-token tests) ───────────────────────────

_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "demo_private_key.pem")

# Minimal payload that passes all Step 4 validations; override individual fields
# to produce specific failure conditions.
_VALID_PAYLOAD: dict = {
    "eid": "f1e2d3c4-b5a6-4789-0abc-def123456789",
    "did": "dev-9f8e7d6c5b4a3c2d",
    "kid": DEMO_KID,
    "ts": 1709312400000,
    "seq": 1044,
    "event_name": "payment.initiated",
    "tctx": "tctx-7c4e9a2f1b8d3e56",
    "sig_ref": {"ledger_seq": 1044, "segment_id": 1},
}


def _make_token(payload: dict, header_kid: str = DEMO_KID, extra_header: dict = None) -> str:
    """Sign *payload* with the demo private key and return a compact JWS string.

    Use this to craft tokens with arbitrary claim values (e.g., wrong types,
    missing fields) to test Step 4 validation logic without touching the
    pre-generated test-vector files.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as _decode

    with open(_PRIVATE_KEY_PATH, "rb") as f:
        private_key = _ser.load_pem_private_key(f.read(), password=None)

    header = {"alg": "ES256", "kid": header_kid, "typ": "JWS"}
    if extra_header:
        header.update(extra_header)
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}".encode()
    der_sig = private_key.sign(signing_input, _ec.ECDSA(_hashes.SHA256()))
    r, s = _decode(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ── Valid token tests ─────────────────────────────────────────────────────────

class TestValidTokens:
    def test_minimal_profile(self, verifier):
        v = load_vector("valid/minimal_profile.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert result.claims["event_name"] == "payment.initiated"
        assert result.claims["seq"] == 1044

    def test_standard_profile(self, verifier):
        v = load_vector("valid/standard_profile.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert result.claims.get("scope") == "payment"
        assert result.claims.get("schema_v") == 1

    def test_payment_retry(self, verifier):
        v = load_vector("valid/payment_retry.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert result.claims["event_name"] == "payment.retry"
        assert result.claims["seq"] == 1045

    def test_claims_returned(self, verifier):
        """Verified result must include parsed claims."""
        v = load_vector("valid/minimal_profile.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.claims is not None
        for field in ["eid", "did", "kid", "ts", "seq", "event_name", "tctx", "sig_ref"]:
            assert field in result.claims, f"Missing claim: {field}"


# ── Signature tests ───────────────────────────────────────────────────────────

class TestSignatureForged:
    def test_wrong_key(self, verifier):
        """Token signed with an unknown/attacker key must be rejected."""
        v = load_vector("invalid/signature_forged/wrong_key.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "signature" in result.reason.lower() or "invalid" in result.reason.lower()

    def test_corrupted_signature(self, verifier):
        """Token with a corrupted signature byte must be rejected."""
        v = load_vector("invalid/signature_forged/corrupted_signature.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_empty_signature(self, verifier):
        """Token with empty signature segment must be rejected."""
        v = load_vector("invalid/signature_forged/empty_signature.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_unknown_kid(self, key_store):
        """Token claiming an unregistered kid must be rejected after re-fetch fails."""
        v = load_vector("invalid/signature_forged/unknown_kid.json")
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "kid" in result.reason.lower() or "unknown" in result.reason.lower()


# ── Algorithm confusion tests ─────────────────────────────────────────────────

class TestAlgorithmConfusion:
    def test_hs256_rejected(self, verifier):
        """Token claiming HS256 (symmetric HMAC) must be rejected."""
        v = load_vector("invalid/algorithm_confusion/hs256_claim.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "algorithm" in result.reason.lower() or "alg" in result.reason.lower()

    def test_alg_none_rejected(self, verifier):
        """Token declaring alg=none must be rejected immediately."""
        v = load_vector("invalid/algorithm_confusion/alg_none.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT


# ── Freshness tests ───────────────────────────────────────────────────────────

class TestFreshness:
    def test_expired_token_rejected(self, key_store):
        """Token 1 hour old must be rejected when freshness is enforced."""
        v = load_vector("invalid/expired_token/one_hour_old.json")
        verifier = EvidenceTokenVerifier(key_store)  # freshness enabled
        result = verifier.verify(v["token"])
        assert result.status == VerificationStatus.REJECT
        assert "freshness" in result.reason.lower()

    def test_future_token_rejected(self, key_store):
        """Token dated 1 hour in the future must be rejected."""
        v = load_vector("invalid/expired_token/future_dated.json")
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(v["token"])
        assert result.status == VerificationStatus.REJECT
        assert "freshness" in result.reason.lower()

    def test_configurable_freshness_window(self, key_store):
        """Verifier must respect operator-configured freshness window."""
        v = load_vector("invalid/expired_token/one_hour_old.json")
        # Decode the token's ts so the window is always wide enough for this static
        # fixture, regardless of how old the vector has become since it was generated.
        payload_b64 = v["token"].split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        ts = json.loads(base64.urlsafe_b64decode(payload_b64))["ts"]
        age_ms = int(time.time() * 1000) - ts
        wide_verifier = EvidenceTokenVerifier(key_store, freshness_window_ms=age_ms + 60_000)
        result = wide_verifier.verify(v["token"])
        assert result.status == VerificationStatus.VALID


# ── Replay tests ──────────────────────────────────────────────────────────────

class TestReplay:
    def test_duplicate_rejected_on_second_submission(self, key_store):
        """The same valid token submitted twice: second must be rejected."""
        v = load_vector("invalid/replay_attack/duplicate_submission.json")
        verifier = EvidenceTokenVerifier(key_store)
        first = verifier.verify(v["token"], skip_freshness=True)
        assert first.status == VerificationStatus.VALID

        second = verifier.verify(v["token"], skip_freshness=True)
        assert second.status == VerificationStatus.REJECT
        assert "duplicate" in second.reason.lower()

    def test_distinct_tokens_not_flagged(self, key_store):
        """Distinct tokens (different eid/seq) must not trigger dedup."""
        verifier = EvidenceTokenVerifier(key_store)
        v1 = load_vector("valid/minimal_profile.json")
        v2 = load_vector("valid/payment_retry.json")

        r1 = verifier.verify(v1["token"], skip_freshness=True)
        r2 = verifier.verify(v2["token"], skip_freshness=True)
        assert r1.status == VerificationStatus.VALID
        assert r2.status == VerificationStatus.VALID


# ── Missing fields tests ──────────────────────────────────────────────────────

class TestMissingFields:
    @pytest.mark.parametrize("field", [
        "eid", "did", "kid", "ts", "seq", "event", "tctx", "sig_ref"
    ])
    def test_missing_required_field(self, verifier, field):
        """Any missing required field must cause rejection."""
        v = load_vector(f"invalid/missing_fields/missing_{field}.json")
        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, \
            f"Expected REJECT for missing '{field}' but got {result.status}: {result.reason}"


# ── Sequence regression tests ─────────────────────────────────────────────────

class TestSequenceRegression:
    def test_retry_with_lower_seq_rejected(self, key_store):
        """payment.retry with seq lower than prior attempt must be rejected."""
        v = load_vector("invalid/sequence_regression/seq_lower_than_prior.json")
        prior_seq = v["prior_seq"]

        verifier = EvidenceTokenVerifier(key_store)
        # Seed the flow store with a prior attempt at seq=prior_seq
        prior_claims = {
            "did": "dev-9f8e7d6c5b4a3c2d",
            "tctx": "tctx-7c4e9a2f1b8d3e56",
            "event_name": "payment.initiated",
            "seq": prior_seq,
            "boot_id": "f0e1d2c3-b4a5-6789-abcd-ef0123456789"
        }
        verifier.flow_store["tctx-7c4e9a2f1b8d3e56"] = [prior_claims]

        result = verifier.verify(v["token"], skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "sequence" in result.reason.lower() or "seq" in result.reason.lower()


# ── Chain integrity tests ─────────────────────────────────────────────────────

class TestChainIntegrity:
    def test_valid_chain(self, record_verifier):
        """Chain across two valid records must verify cleanly."""
        r1 = load_record("demo_sequence/ledger_record_attempt1.json")
        r2 = load_record("demo_sequence/ledger_record_attempt2.json")
        result = record_verifier.verify_chain([r1, r2])
        assert result.status == VerificationStatus.VALID, result.reason

    def test_tampered_prev_hash(self, record_verifier):
        """Record with tampered prev_hash must break chain verification."""
        v = load_vector("invalid/broken_chain/tampered_prev_hash.json")
        r1 = load_record("demo_sequence/ledger_record_attempt1.json")
        r2 = v["record"]
        result = record_verifier.verify_chain([r1, r2])
        assert result.status == VerificationStatus.REJECT
        assert "chain" in result.reason.lower() or "hash" in result.reason.lower()

    def test_tampered_record_content(self, record_verifier):
        """Record with modified content must fail event_hash verification."""
        v = load_vector("invalid/broken_chain/event_hash_mismatch.json")
        result = record_verifier.verify_chain([v["record"]])
        assert result.status == VerificationStatus.REJECT

    def test_record_signature_valid(self, record_verifier):
        """Full Evidence Record signature must verify correctly."""
        r = load_record("full_evidence_record.json")
        result = record_verifier.verify(r)
        assert result.status == VerificationStatus.VALID, result.reason

    def test_auth_payment_chain(self, record_verifier):
        """Auth → Payment chain in chargeback scenario must verify."""
        r_auth = load_record("chargeback_dispute/ledger_record_auth.json")
        r_pay = load_record("chargeback_dispute/ledger_record_payment.json")
        result = record_verifier.verify_chain([r_auth, r_pay])
        assert result.status == VerificationStatus.VALID, result.reason



# ── Trust level tests ─────────────────────────────────────────────────────────

class TestRecordTsSource:
    def test_missing_ts_source_rejects(self, key_store):
        """Missing ts_source must cause rejection."""
        r = load_record("full_evidence_record.json")
        r_no_ts = {k: v for k, v in r.items() if k != "ts_source"}
        rv = EvidenceRecordVerifier(key_store)
        result = rv.verify(r_no_ts)
        assert result.status == VerificationStatus.REJECT
        assert "ts_source" in result.reason

    def test_unknown_ts_source_produces_warning(self, key_store):
        """Unknown ts_source must generate a warning; a record without sig rejects on sig."""
        fake_record = {"ts_source": "gps_satellite"}
        rv = EvidenceRecordVerifier(key_store)
        result = rv.verify(fake_record)
        # Rejects on missing sig, but not on ts_source (ts_source warning is accumulated)
        assert result.status == VerificationStatus.REJECT
        assert "sig" in result.reason.lower()

    def test_valid_ts_source_accepted(self, record_verifier):
        """A record with a recognised ts_source must verify successfully."""
        r = load_record("full_evidence_record.json")
        result = record_verifier.verify(r)
        assert result.status == VerificationStatus.VALID, result.reason


class TestTrustLevel:
    def test_hardware_backed_trust(self):
        record = {"attestation_ref": {"device_state": "verified"}}
        assert evaluate_trust(record) == TrustLevel.HARDWARE_BACKED

    def test_unknown_state_trust(self):
        record = {"attestation_ref": {"device_state": "unknown"}}
        assert evaluate_trust(record) == TrustLevel.EXECUTION_PROOF

    def test_failed_state_trust(self):
        record = {"attestation_ref": {"device_state": "failed"}}
        assert evaluate_trust(record) == TrustLevel.COMPROMISED_DEVICE

    def test_no_attestation_trust(self):
        record = {}
        assert evaluate_trust(record) == TrustLevel.SOFTWARE_LAYER

    def test_full_record_trust_level(self, record_verifier):
        r = load_record("full_evidence_record.json")
        result = record_verifier.verify(r)
        assert result.trust_level == TrustLevel.HARDWARE_BACKED

    def test_hardware_keystore_trust(self):
        """device_state 'hardware_keystore' must map to HARDWARE_BOUND trust."""
        record = {"attestation_ref": {"device_state": "hardware_keystore"}}
        assert evaluate_trust(record) == TrustLevel.HARDWARE_BOUND

    def test_unknown_device_state_falls_back_to_software_layer(self):
        """Any unrecognised device_state string must fall through to SOFTWARE_LAYER."""
        record = {"attestation_ref": {"device_state": "purple_unicorn"}}
        assert evaluate_trust(record) == TrustLevel.SOFTWARE_LAYER

    def test_record_sig_algo_non_es256_rejected(self, record_verifier):
        """Evidence Record with sig.algo != ES256 must be rejected."""
        r = load_record("full_evidence_record.json")
        tampered = {**r, "sig": {**r["sig"], "algo": "HS256"}}
        result = record_verifier.verify(tampered)
        assert result.status == VerificationStatus.REJECT
        assert "algo" in result.reason.lower() or "algorithm" in result.reason.lower()

    def test_record_chain_wrong_hash_algo_rejected(self, record_verifier):
        """Evidence Record with chain_ref.hash_algo != sha-256 must be rejected in verify_chain."""
        r = load_record("full_evidence_record.json")
        tampered = {**r, "chain_ref": {**r["chain_ref"], "hash_algo": "sha-512"}}
        result = record_verifier.verify_chain([tampered])
        assert result.status == VerificationStatus.REJECT
        assert "hash_algo" in result.reason.lower() or "sha-256" in result.reason.lower()

    def test_signal_future_measured_at_rejected(self, record_verifier):
        """A signal measured more than 5 s after the record ts must cause rejection."""
        r = load_record("full_evidence_record.json")
        future_ts = r["ts"] + 120_000  # 2 minutes after record ts — well above tolerance
        tampered = {
            **r,
            "signals": [
                {
                    "signal": "device.integrity",
                    "source": "bootloader",
                    "measured_at": future_ts,
                    "value": "verified",
                    "measurement_method": "hardware_attested",
                }
            ],
        }
        result = record_verifier.verify(tampered)
        assert result.status == VerificationStatus.REJECT
        assert "measured_at" in result.reason.lower()


# ── Utility function unit tests ───────────────────────────────────────────────

from verifier import _b64url_decode, _is_valid_uuid  # noqa: E402


class TestUtilityB64urlDecode:
    """Unit tests for _b64url_decode — covers padding restoration and URL-safe char mapping."""

    def test_3_byte_input_no_padding_needed(self):
        # 3 bytes → 4 b64 chars → 4 % 4 == 0, no padding needed
        data = b"abc"
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert len(encoded) % 4 == 0
        assert _b64url_decode(encoded) == data

    def test_1_byte_input_adds_double_padding(self):
        # 1 byte → 2 b64 chars → needs "==" padding
        data = b"a"
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert len(encoded) % 4 == 2
        assert _b64url_decode(encoded) == data

    def test_2_byte_input_adds_single_padding(self):
        # 2 bytes → 3 b64 chars → needs "=" padding
        data = b"ab"
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert len(encoded) % 4 == 3
        assert _b64url_decode(encoded) == data

    def test_url_safe_chars_roundtrip(self):
        # Bytes that produce + and / in standard b64 → - and _ in url-safe b64
        data = bytes([0xFB, 0xEF, 0x12, 0x34])
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert _b64url_decode(encoded) == data

    def test_empty_string(self):
        assert _b64url_decode("") == b""

    def test_non_ascii_bytes_roundtrip(self):
        # Bytes outside ASCII range (produce + and / in standard b64)
        data = bytes(range(0, 16))
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert _b64url_decode(encoded) == data


class TestUtilityIsValidUuid:
    """Unit tests for _is_valid_uuid."""

    def test_valid_lowercase_uuid(self):
        assert _is_valid_uuid("f1e2d3c4-b5a6-4789-0abc-def123456789") is True

    def test_valid_uppercase_uuid(self):
        assert _is_valid_uuid("F1E2D3C4-B5A6-4789-0ABC-DEF123456789") is True

    def test_valid_mixed_case_uuid(self):
        assert _is_valid_uuid("f1e2D3c4-B5a6-4789-0AbC-dEf123456789") is True

    def test_invalid_too_short(self):
        assert _is_valid_uuid("f1e2d3c4-b5a6-4789") is False

    def test_invalid_wrong_length(self):
        # 35 chars (one short) — wrong length
        assert _is_valid_uuid("f1e2d3c4-b5a6-4789-0abc-def12345678") is False

    def test_invalid_empty_string(self):
        assert _is_valid_uuid("") is False

    def test_invalid_non_hex_chars(self):
        assert _is_valid_uuid("f1e2d3c4-b5a6-4789-0abc-zzzzzzzzzzzz") is False

    def test_invalid_integer_input(self):
        # Must not raise — must return False for non-string input
        assert _is_valid_uuid(12345) is False

    def test_invalid_braced_uuid(self):
        # Python uuid.UUID() accepts braced format (38 chars) but _is_valid_uuid must not.
        # Go and JS both reject this — cross-impl consistency requirement.
        assert _is_valid_uuid("{f1e2d3c4-b5a6-4789-0abc-def123456789}") is False

    def test_invalid_urn_uuid(self):
        # URN form (45 chars) must be rejected — not a valid token UUID format.
        assert _is_valid_uuid("urn:uuid:f1e2d3c4-b5a6-4789-0abc-def123456789") is False


# ── KeyStore unit tests ───────────────────────────────────────────────────────

class TestKeyStore:
    """Unit tests for KeyStore: register, lookup, refetch, load_pem_bytes."""

    def test_register_and_lookup(self, key_store):
        key = key_store.lookup(DEMO_KID)
        assert key is not None

    def test_lookup_unknown_kid_returns_none(self, key_store):
        assert key_store.lookup("nonexistent.kid.v99") is None

    def test_refetch_base_returns_none(self, key_store):
        # Base implementation always returns None (override in production)
        assert key_store.refetch("any.kid") is None

    def test_load_pem_bytes(self):
        store = KeyStore()
        pem_path = os.path.join(KEYS_DIR, "demo_public_key.pem")
        with open(pem_path, "rb") as f:
            pem_bytes = f.read()
        store.load_pem_bytes(DEMO_KID, pem_bytes)
        assert store.lookup(DEMO_KID) is not None

    def test_register_overwrites_existing(self, key_store):
        old_key = key_store.lookup(DEMO_KID)
        key_store.register(DEMO_KID, old_key)  # re-register same key object
        assert key_store.lookup(DEMO_KID) is old_key

    def test_multiple_keys(self):
        store = KeyStore()
        pem_path = os.path.join(KEYS_DIR, "demo_public_key.pem")
        store.load_pem(DEMO_KID, pem_path)
        store.load_pem("other.kid.v1", pem_path)
        assert store.lookup(DEMO_KID) is not None
        assert store.lookup("other.kid.v1") is not None


# ── VerificationResult unit tests ─────────────────────────────────────────────

class TestVerificationResultBool:
    """Unit tests for VerificationResult.__bool__."""

    def test_valid_result_is_truthy(self):
        r = VerificationResult(VerificationStatus.VALID)
        assert bool(r) is True

    def test_reject_result_is_falsy(self):
        r = VerificationResult(VerificationStatus.REJECT, reason="test error")
        assert bool(r) is False


# ── Non-regression tests for BUG-1: Python bool is subclass of int ────────────

class TestNonRegressionBoolAsInt:
    """Non-regression for BUG-1: isinstance(True, int) is True in Python.

    Without the explicit `isinstance(x, bool)` guard, a payload with seq=true
    or ts=true would silently pass integer validation.
    """

    def test_seq_true_rejected(self, key_store):
        """seq=true (JSON boolean) must be rejected, not treated as integer 1."""
        payload = {**_VALID_PAYLOAD, "seq": True}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason
        assert "seq" in result.reason.lower()

    def test_seq_false_rejected(self, key_store):
        """seq=false (JSON boolean) must be rejected, not treated as integer 0."""
        payload = {**_VALID_PAYLOAD, "seq": False}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason
        assert "seq" in result.reason.lower()

    def test_ts_true_rejected(self, key_store):
        """ts=true (JSON boolean) must be rejected."""
        payload = {**_VALID_PAYLOAD, "ts": True}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason
        assert "ts" in result.reason.lower()

    def test_seq_float_rejected(self, key_store):
        """seq=1.5 (float, not int) must be rejected."""
        payload = {**_VALID_PAYLOAD, "seq": 1.5}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason

    def test_seq_string_rejected(self, key_store):
        """seq='1044' (string, not int) must be rejected."""
        payload = {**_VALID_PAYLOAD, "seq": "1044"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason
        assert "seq" in result.reason.lower()

    def test_ts_string_rejected(self, key_store):
        """ts='1709312400000' (string, not int) must be rejected."""
        payload = {**_VALID_PAYLOAD, "ts": "1709312400000"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT, result.reason
        assert "ts" in result.reason.lower()


# ── SPEC normative security requirement tests ─────────────────────────────────

class TestSpecRequirements:
    """Security tests mapped 1-to-1 to normative MUST/MUST NOT requirements in SPEC.md.

    These tests exercise SPEC Step 4 validations using freshly-signed tokens
    to ensure correctness independently of the pre-generated test-vector files.
    """

    def test_kid_mismatch_header_payload_rejected(self, key_store):
        """SPEC Step 4: kid in JWS header and payload MUST be identical."""
        # Header kid is registered; payload kid is different — Step 4 must catch it.
        payload = {**_VALID_PAYLOAD, "kid": "other.unknown.kid"}
        token = _make_token(payload, header_kid=DEMO_KID)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "kid" in result.reason.lower() or "mismatch" in result.reason.lower()

    def test_tctx_empty_string_rejected(self, key_store):
        """SPEC Step 4: tctx MUST be non-empty."""
        payload = {**_VALID_PAYLOAD, "tctx": ""}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "tctx" in result.reason.lower()

    def test_tctx_with_space_rejected(self, key_store):
        """SPEC Step 4: tctx MUST NOT contain whitespace."""
        payload = {**_VALID_PAYLOAD, "tctx": "tctx with space"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "tctx" in result.reason.lower()

    def test_tctx_with_tab_rejected(self, key_store):
        """SPEC Step 4: tctx MUST NOT contain tab character."""
        payload = {**_VALID_PAYLOAD, "tctx": "tctx\twith\ttab"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_tctx_c1_control_0x80_rejected(self, key_store):
        """SPEC Step 4: tctx MUST NOT contain C1 control characters (U+0080–U+009F)."""
        payload = {**_VALID_PAYLOAD, "tctx": "tctx\x80bad"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_tctx_c1_control_0x9f_rejected(self, key_store):
        """SPEC Step 4: tctx MUST NOT contain C1 control characters (U+0080–U+009F)."""
        payload = {**_VALID_PAYLOAD, "tctx": "tctx\x9fbad"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_boot_id_invalid_uuid_rejected(self, key_store):
        """SPEC Step 4: boot_id, when present, MUST be a valid UUID."""
        payload = {**_VALID_PAYLOAD, "boot_id": "not-a-uuid-at-all"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "boot_id" in result.reason.lower()

    def test_schema_v_unknown_produces_warning_not_reject(self, key_store):
        """SPEC Step 4: unknown schema_v MUST produce a warning, not a rejection."""
        payload = {**_VALID_PAYLOAD, "schema_v": 99}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert any("schema_v" in w for w in result.warnings)

    def test_sig_ref_segment_id_absent_produces_warning_not_reject(self, key_store):
        """SPEC Step 4: absent segment_id MUST warn (backward compat), not reject."""
        payload = {**_VALID_PAYLOAD, "sig_ref": {"ledger_seq": 1044}}  # no segment_id
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert any("segment_id" in w for w in result.warnings)

    def test_event_name_takes_precedence_when_both_present(self, key_store):
        """SPEC Step 4: when both event_name and event are present, event_name wins."""
        payload = {**_VALID_PAYLOAD, "event_name": "payment.initiated", "event": "legacy.ignored"}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason
        assert result.claims["event_name"] == "payment.initiated"

    def test_unknown_extra_fields_accepted(self, key_store):
        """SPEC: Unknown payload fields MUST be ignored for forward compatibility."""
        payload = {**_VALID_PAYLOAD, "future_field": "value", "another_new_field": 42}
        token = _make_token(payload)
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.VALID, result.reason

    def test_malformed_jws_two_segments_rejected(self, key_store):
        """SPEC Step 1: JWS with only 2 segments (missing signature) MUST be rejected."""
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify("header.payload", skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "3" in result.reason or "segment" in result.reason.lower()

    def test_malformed_jws_empty_string_rejected(self, key_store):
        """SPEC Step 1: empty token string MUST be rejected."""
        verifier = EvidenceTokenVerifier(key_store)
        result = verifier.verify("", skip_freshness=True)
        assert result.status == VerificationStatus.REJECT


# ── verify_chain edge case tests ──────────────────────────────────────────────

class TestVerifyChainEdgeCases:
    """Edge cases and non-regression tests for EvidenceRecordVerifier.verify_chain."""

    def test_empty_list_returns_valid(self, record_verifier):
        """Empty record list must return VALID (no chain to violate)."""
        result = record_verifier.verify_chain([])
        assert result.status == VerificationStatus.VALID

    def test_out_of_order_records_sorted_and_valid(self, record_verifier):
        """Records provided in reverse seq order must be sorted and verify correctly."""
        r1 = load_record("demo_sequence/ledger_record_attempt1.json")
        r2 = load_record("demo_sequence/ledger_record_attempt2.json")
        # Supply in reverse order — verify_chain MUST sort by seq internally.
        result = record_verifier.verify_chain([r2, r1])
        assert result.status == VerificationStatus.VALID, result.reason

    def test_missing_chain_ref_rejected(self, record_verifier):
        """Record without chain_ref must be rejected cleanly (not crash)."""
        record = {"seq": 1, "ts": 1709312400000}  # chain_ref absent
        result = record_verifier.verify_chain([record])
        assert result.status == VerificationStatus.REJECT

    def test_missing_event_hash_rejected_cleanly(self, record_verifier):
        """Non-regression for BUG-2: missing event_hash must REJECT without TypeError."""
        record = {
            "seq": 1,
            "ts": 1709312400000,
            "chain_ref": {
                "hash_algo": "sha-256",
                "prev_hash": "0" * 64,
                # event_hash intentionally absent — tests (event_hash or '')[:16] fix
            },
        }
        result = record_verifier.verify_chain([record])
        assert result.status == VerificationStatus.REJECT
        # Verify no crash and a meaningful message
        assert result.reason is not None

    def test_wrong_hash_algo_in_chain_rejected(self, record_verifier):
        """chain_ref.hash_algo != 'sha-256' must be rejected."""
        record = {
            "seq": 1,
            "ts": 1709312400000,
            "chain_ref": {
                "hash_algo": "sha-512",
                "event_hash": "0" * 64,
                "prev_hash": "0" * 64,
            },
        }
        result = record_verifier.verify_chain([record])
        assert result.status == VerificationStatus.REJECT
        assert "sha-256" in result.reason or "hash_algo" in result.reason.lower()


class TestProductionRequirements:
    """SPEC.md — Production implementation requirements."""

    def test_disallowed_jws_header_key_rejected(self, verifier):
        token = _make_token(
            dict(_VALID_PAYLOAD),
            extra_header={"jwk": {"kty": "EC", "crv": "P-256"}},
        )
        result = verifier.verify(token, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "disallowed" in result.reason.lower() or "jwk" in result.reason.lower()

    def test_oversized_token_rejected(self, verifier):
        result = verifier.verify("x" * 25000, skip_freshness=True)
        assert result.status == VerificationStatus.REJECT
        assert "maximum size" in result.reason.lower() or "exceeds" in result.reason.lower()

    def test_negative_seq_rejected(self, verifier):
        p = {**_VALID_PAYLOAD, "seq": -1}
        result = verifier.verify(_make_token(p), skip_freshness=True)
        assert result.status == VerificationStatus.REJECT

    def test_token_record_binding_ok(self):
        claims = {
            "eid": "f1e2d3c4-b5a6-4789-0abc-def123456789",
            "did": "dev-9f8e7d6c5b4a3c2d",
            "tctx": "tctx-7c4e9a2f1b8d3e56",
            "seq": 1044,
            "sig_ref": {"ledger_seq": 1044, "segment_id": 12},
        }
        record = {
            "eid": "f1e2d3c4-b5a6-4789-0abc-def123456789",
            "device_id": "dev-9f8e7d6c5b4a3c2d",
            "tctx": "tctx-7c4e9a2f1b8d3e56",
            "seq": 1044,
            "chain_ref": {"ledger_seq": 1044, "segment_id": 12},
        }
        assert verify_token_record_binding(claims, record) is None

    def test_token_record_binding_rejects_eid_mismatch(self):
        claims = {
            "eid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "did": "dev-9f8e7d6c5b4a3c2d",
            "tctx": "tctx-7c4e9a2f1b8d3e56",
            "seq": 1044,
            "sig_ref": {"ledger_seq": 1044},
        }
        record = {
            "eid": "f1e2d3c4-b5a6-4789-0abc-def123456789",
            "device_id": "dev-9f8e7d6c5b4a3c2d",
            "tctx": "tctx-7c4e9a2f1b8d3e56",
            "seq": 1044,
            "chain_ref": {"ledger_seq": 1044},
        }
        assert verify_token_record_binding(claims, record) is not None

    def test_verify_chain_accepts_uppercase_event_hash(self, record_verifier):
        r1 = load_record("demo_sequence/ledger_record_attempt1.json")
        r2 = load_record("demo_sequence/ledger_record_attempt2.json")
        r1u = json.loads(json.dumps(r1))
        eh = r1u["chain_ref"]["event_hash"]
        r1u["chain_ref"]["event_hash"] = eh.upper()
        result = record_verifier.verify_chain([r1u, r2])
        assert result.status == VerificationStatus.VALID, result.reason
