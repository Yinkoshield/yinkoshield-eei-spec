# Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
#
# YinkoShield Execution Evidence Infrastructure
# Evidence Token Verifier — Python Reference Implementation
#
# This is a reference implementation of the verification pipeline defined in SPEC.md.
# It demonstrates sovereign verification: no YinkoShield infrastructure required.
# Verification uses only the registered device public key.
#
# https://github.com/yinkoshield
"""
YinkoShield Evidence Token Verifier — Python Reference Implementation

Implements the 8-step verification pipeline defined in SPEC.md.

Usage:
    python verifier.py --token <jws_string> --pubkey <path_to_public_key.pem>
    python verifier.py --token-file <path_to.jws> --pubkey <path_to_public_key.pem>

Dependencies:
    pip install cryptography

No YinkoShield infrastructure is required. Verification uses only the registered
device public key (sovereign verification model).
"""

import base64
import hashlib
import json
import time
import uuid
import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
import threading

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


# ── Constants ────────────────────────────────────────────────────────────────

SUPPORTED_SCHEMA_VERSION = 1
DEFAULT_FRESHNESS_WINDOW_MS = 300_000  # 5 minutes
# Canonical field name is event_name; legacy field name 'event' is accepted for backward compat.
REQUIRED_MINIMAL_FIELDS = {"eid", "did", "kid", "ts", "seq", "tctx", "sig_ref"}  # event_name/event checked separately
VALID_ALGORITHMS = {"ES256"}
VALID_TS_SOURCES = {"secure_clock", "ntp", "rtc"}
SIGNAL_CLOCK_SKEW_TOLERANCE_MS = 5_000  # max ms a signal's measured_at may exceed record ts

# Production limits — SPEC.md "Production implementation requirements"
MAX_JWS_COMPACT_UTF8_BYTES = 24_576
MAX_JWS_HEADER_DECODED_BYTES = 2_048
MAX_JWS_PAYLOAD_DECODED_BYTES = 12_288
ALLOWED_JWS_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
MAX_HEADER_TYP_LENGTH = 128
MAX_CLAIM_KID_LENGTH = 256
MAX_CLAIM_DID_LENGTH = 128
MAX_CLAIM_TCTX_LENGTH = 256
MAX_CLAIM_EVENT_NAME_LENGTH = 128
MAX_JSON_SAFE_INTEGER = 9_007_199_254_740_991  # 2**53 - 1
MIN_TS_MS_RECOMMENDED = 1_000_000_000_000  # ~2001-09-09 UTC


# ── Result types ─────────────────────────────────────────────────────────────


class TrustLevel(Enum):
    HARDWARE_BACKED = "hardware_backed"      # TEE with full attestation certificate
    HARDWARE_BOUND = "hardware_bound"        # Hardware Keystore, no TEE attestation cert
    EXECUTION_PROOF = "execution_proof"      # Platform state indeterminate
    COMPROMISED_DEVICE = "compromised_device"  # Integrity failed; evidence recorded
    SOFTWARE_LAYER = "software_layer"        # No platform binding


class VerificationStatus(Enum):
    VALID = "valid"
    REJECT = "reject"


@dataclass
class VerificationResult:
    status: VerificationStatus
    reason: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
    trust_level: Optional[TrustLevel] = None
    warnings: List[str] = field(default_factory=list)

    def __bool__(self):
        return self.status == VerificationStatus.VALID


# ── Key store (simple in-memory implementation for demo) ─────────────────────


class KeyStore:
    """
    Maps kid → public key. In production, back this with your device onboarding
    database. Supports re-fetch on unknown kid (key rotation handling).
    """

    def __init__(self):
        self._store: Dict[str, Any] = {}

    def register(self, kid: str, public_key) -> None:
        self._store[kid] = public_key

    def load_pem(self, kid: str, pem_path: str) -> None:
        with open(pem_path, "rb") as f:
            key = serialization.load_pem_public_key(f.read())
        self.register(kid, key)

    def load_pem_bytes(self, kid: str, pem_bytes: bytes) -> None:
        key = serialization.load_pem_public_key(pem_bytes)
        self.register(kid, key)

    def lookup(self, kid: str):
        return self._store.get(kid)

    def refetch(self, kid: str):
        """
        Override in production to query your onboarding service.
        Returns None if key is genuinely unknown.
        """
        return None


# ── Utility functions ─────────────────────────────────────────────────────────


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _is_valid_uuid(value: str) -> bool:
    # Require exactly 36 characters (standard UUID form: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
    # Explicitly rejects braced form ({...}, 38 chars) and URN form (urn:uuid:..., 45 chars)
    # which Python's uuid.UUID() would otherwise accept — keeping behaviour consistent with
    # the Go and JavaScript reference implementations.
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


_HEX_CHARS = frozenset("0123456789abcdef")


_MAX_NESTING_DEPTH = 32


def _check_nesting_depth(obj: Any, max_depth: int = _MAX_NESTING_DEPTH, _current: int = 0) -> None:
    """Raise ValueError if obj nesting exceeds max_depth.

    Python's json.dumps recurses without a depth limit; adversarially crafted
    Evidence Records with extreme nesting could cause a stack overflow before
    any size-based limit fires.  Call this before any json.dumps on untrusted input.
    """
    if _current > max_depth:
        raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth})")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_nesting_depth(v, max_depth, _current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_nesting_depth(item, max_depth, _current + 1)


def _normalize_hex64(value: Any) -> Optional[str]:
    """Return lowercase hex if *value* is exactly 64 hex digits; else None."""
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    if not all(c in _HEX_CHARS for c in lowered):
        return None
    return lowered


def _reject_if_overlong_utf8(token: str) -> Optional[str]:
    if len(token.encode("utf-8")) > MAX_JWS_COMPACT_UTF8_BYTES:
        return (
            f"Step 1: JWS compact token exceeds maximum size "
            f"({MAX_JWS_COMPACT_UTF8_BYTES} UTF-8 bytes)"
        )
    return None


def _production_validate_jws_header(jws_header: Dict[str, Any]) -> Optional[str]:
    extra = set(jws_header.keys()) - ALLOWED_JWS_HEADER_KEYS
    if extra:
        return f"Step 1: disallowed JWS header key(s): {sorted(extra)}"
    alg = jws_header.get("alg")
    kid = jws_header.get("kid")
    if not isinstance(alg, str):
        return "Step 1: JWS header 'alg' must be a string"
    if not isinstance(kid, str):
        return "Step 1: JWS header 'kid' must be a string"
    if "typ" in jws_header:
        typ = jws_header["typ"]
        if not isinstance(typ, str):
            return "Step 1: JWS header 'typ' must be a string"
        if len(typ) > MAX_HEADER_TYP_LENGTH:
            return f"Step 1: JWS header 'typ' exceeds max length {MAX_HEADER_TYP_LENGTH}"
    return None


def _production_validate_token_strings(claims: Dict[str, Any]) -> Optional[str]:
    kid = claims.get("kid")
    if isinstance(kid, str) and len(kid) > MAX_CLAIM_KID_LENGTH:
        return f"Step 4: 'kid' exceeds max length {MAX_CLAIM_KID_LENGTH}"
    did = claims.get("did")
    if isinstance(did, str) and len(did) > MAX_CLAIM_DID_LENGTH:
        return f"Step 4: 'did' exceeds max length {MAX_CLAIM_DID_LENGTH}"
    tctx = claims.get("tctx")
    if isinstance(tctx, str) and len(tctx) > MAX_CLAIM_TCTX_LENGTH:
        return f"Step 4: 'tctx' exceeds max length {MAX_CLAIM_TCTX_LENGTH}"
    en = claims.get("event_name")
    if isinstance(en, str) and len(en) > MAX_CLAIM_EVENT_NAME_LENGTH:
        return f"Step 4: 'event_name' exceeds max length {MAX_CLAIM_EVENT_NAME_LENGTH}"
    return None


def _production_validate_token_integers(claims: Dict[str, Any]) -> Optional[str]:
    def check(name: str, v: Any) -> Optional[str]:
        if not isinstance(v, int) or isinstance(v, bool):
            return f"Step 4: '{name}' must be an integer"
        if v < 0 or v > MAX_JSON_SAFE_INTEGER:
            return f"Step 4: '{name}' out of allowed range [0, {MAX_JSON_SAFE_INTEGER}]"
        return None

    r = check("ts", claims.get("ts"))
    if r:
        return r
    r = check("seq", claims.get("seq"))
    if r:
        return r
    if claims["ts"] < MIN_TS_MS_RECOMMENDED:
        return f"Step 4: 'ts' is below minimum allowed ({MIN_TS_MS_RECOMMENDED} ms epoch)"
    sig_ref = claims.get("sig_ref")
    if isinstance(sig_ref, dict):
        ls = sig_ref.get("ledger_seq")
        r = check("sig_ref.ledger_seq", ls)
        if r:
            return r
        if "segment_id" in sig_ref:
            r = check("sig_ref.segment_id", sig_ref.get("segment_id"))
            if r:
                return r
    return None


def verify_token_record_binding(
    claims: Dict[str, Any], record: Dict[str, Any]
) -> Optional[str]:
    """
    Validate token ↔ record field equality (SPEC — Production implementation requirements).
    Returns None if OK, else a human-readable rejection reason.
    Does not verify signatures; call EvidenceTokenVerifier.verify and EvidenceRecordVerifier.verify first.
    """
    if claims.get("eid") != record.get("eid"):
        return "Binding: token eid does not match record eid"
    if claims.get("did") != record.get("device_id"):
        return "Binding: token did does not match record device_id"
    if claims.get("tctx") != record.get("tctx"):
        return "Binding: token tctx does not match record tctx"
    if claims.get("seq") != record.get("seq"):
        return "Binding: token seq does not match record seq"
    sig_ref = claims.get("sig_ref")
    chain_ref = record.get("chain_ref")
    if not isinstance(sig_ref, dict) or not isinstance(chain_ref, dict):
        return "Binding: sig_ref or chain_ref missing or not an object"
    if sig_ref.get("ledger_seq") != chain_ref.get("ledger_seq"):
        return "Binding: sig_ref.ledger_seq does not match chain_ref.ledger_seq"
    if "segment_id" in sig_ref and "segment_id" in chain_ref:
        if sig_ref.get("segment_id") != chain_ref.get("segment_id"):
            return "Binding: sig_ref.segment_id does not match chain_ref.segment_id"
    return None


# ── Core verifier ─────────────────────────────────────────────────────────────


class EvidenceTokenVerifier:
    """
    Verifies a YinkoShield Evidence Token (JWS compact) following the 8-step
    pipeline in SPEC.md § Verification.

    Example:
        store = KeyStore()
        store.load_pem("yinkoshield.device.sign.v1", "keys/demo_public_key.pem")
        verifier = EvidenceTokenVerifier(store)
        result = verifier.verify(token_string)
        if result:
            print(result.claims)
    """

    def __init__(
        self,
        key_store: KeyStore,
        freshness_window_ms: int = DEFAULT_FRESHNESS_WINDOW_MS,
        dedup_store: Optional[Dict] = None,
        flow_store: Optional[Dict] = None,
    ):
        self.key_store = key_store
        self.freshness_window_ms = freshness_window_ms
        # dedup_store maps dedup_key → expiry_ms; entries are pruned when expired.
        self.dedup_store: Dict = dedup_store if dedup_store is not None else {}
        self.flow_store: Dict = flow_store if flow_store is not None else {}
        self._dedup_lock = threading.Lock()
        self._flow_lock = threading.Lock()

    def verify(self, token: str, skip_freshness: bool = False) -> VerificationResult:
        """
        Full 8-step verification. Returns VerificationResult.
        Steps fail closed: any failure returns REJECT immediately.

        Args:
            token: JWS compact string
            skip_freshness: Set True only for testing against static fixtures
        """
        warnings: List[str] = []

        # ── Step 1: Parse JWS structure ──────────────────────────────────────
        token = token.strip()
        lim = _reject_if_overlong_utf8(token)
        if lim:
            return VerificationResult(VerificationStatus.REJECT, reason=lim)
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason="Malformed JWS: expected 3 dot-separated segments",
                )
            header_b64, payload_b64, sig_b64 = parts
            header_raw = _b64url_decode(header_b64)
            if len(header_raw) > MAX_JWS_HEADER_DECODED_BYTES:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=(
                        f"Step 1: JWS header exceeds maximum decoded size "
                        f"({MAX_JWS_HEADER_DECODED_BYTES} bytes)"
                    ),
                )
            jws_payload_bytes = _b64url_decode(payload_b64)
            if len(jws_payload_bytes) > MAX_JWS_PAYLOAD_DECODED_BYTES:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=(
                        f"Step 1: JWS payload exceeds maximum decoded size "
                        f"({MAX_JWS_PAYLOAD_DECODED_BYTES} bytes)"
                    ),
                )
            jws_header = json.loads(header_raw)
        except Exception as e:
            return VerificationResult(
                VerificationStatus.REJECT, reason=f"Step 1 (parse): {e}"
            )

        hdr_err = _production_validate_jws_header(jws_header)
        if hdr_err:
            return VerificationResult(VerificationStatus.REJECT, reason=hdr_err)

        if "alg" not in jws_header:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 1: missing 'alg' in JWS header"
            )
        if "kid" not in jws_header:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 1: missing 'kid' in JWS header"
            )

        alg = jws_header["alg"]
        kid = jws_header["kid"]

        if alg not in VALID_ALGORITHMS:
            return VerificationResult(
                VerificationStatus.REJECT,
                reason=f"Step 1: unsupported algorithm '{alg}'. Accepted: {VALID_ALGORITHMS}",
            )

        # ── Step 2: Resolve signing key ──────────────────────────────────────
        public_key = self.key_store.lookup(kid)
        if public_key is None:
            # Unknown kid — may be a key rotation. Attempt re-fetch.
            public_key = self.key_store.refetch(kid)
            if public_key is None:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"Step 2: unknown kid '{kid}'. Device not registered or key rotation not reconciled.",
                )
            self.key_store.register(kid, public_key)

        # ── Step 3: Verify signature ─────────────────────────────────────────
        try:
            signing_input = f"{header_b64}.{payload_b64}".encode()
            raw_sig = _b64url_decode(sig_b64)
            if len(raw_sig) != 64:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"Step 3: invalid ES256 signature length ({len(raw_sig)} bytes, expected 64)",
                )
            r = int.from_bytes(raw_sig[:32], "big")
            s = int.from_bytes(raw_sig[32:], "big")
            der_sig = encode_dss_signature(r, s)
            public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 3: invalid signature"
            )
        except Exception as e:
            return VerificationResult(
                VerificationStatus.REJECT, reason=f"Step 3 (signature): {e}"
            )

        # ── Step 4: Parse and validate claims ────────────────────────────────
        try:
            claims = json.loads(jws_payload_bytes)
        except Exception as e:
            return VerificationResult(
                VerificationStatus.REJECT, reason=f"Step 4 (parse claims): {e}"
            )

        missing = REQUIRED_MINIMAL_FIELDS - set(claims.keys())
        if missing:
            return VerificationResult(
                VerificationStatus.REJECT,
                reason=f"Step 4: missing required fields: {sorted(missing)}",
            )

        # Normalise event field: spec uses 'event_name'; legacy tokens use 'event'.
        # Accept both; normalise to 'event_name' for all downstream processing.
        if "event_name" not in claims:
            if "event" in claims:
                claims = dict(claims)  # make mutable copy before mutation
                claims["event_name"] = claims["event"]
                warnings.append("Step 4: legacy 'event' field found; use 'event_name' in new implementations.")
            else:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason="Step 4: missing required field 'event_name' (or legacy 'event')",
                )

        # Q1: kid in JWS header and payload must be identical — both are signed material,
        # so a mismatch is structurally impossible in a legitimate token.
        if claims.get("kid") != kid:
            return VerificationResult(
                VerificationStatus.REJECT,
                reason=f"Step 4: kid mismatch — header kid='{kid}' != payload kid='{claims.get('kid')}'",
            )

        # Q6: tctx must be a non-empty printable string with no whitespace.
        tctx_val = claims.get("tctx", "")
        if not isinstance(tctx_val, str) or not tctx_val or not tctx_val.isprintable() or any(c.isspace() for c in tctx_val):
            return VerificationResult(
                VerificationStatus.REJECT,
                reason="Step 4: 'tctx' must be a non-empty printable string with no whitespace",
            )

        if not _is_valid_uuid(claims.get("eid", "")):
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 4: 'eid' is not a valid UUID"
            )

        seq_val = claims.get("seq")
        if not isinstance(seq_val, int) or isinstance(seq_val, bool):
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 4: 'seq' must be an integer"
            )

        ts_val = claims.get("ts")
        if not isinstance(ts_val, int) or isinstance(ts_val, bool):
            return VerificationResult(
                VerificationStatus.REJECT, reason="Step 4: 'ts' must be an integer"
            )

        if (
            not isinstance(claims.get("sig_ref"), dict)
            or "ledger_seq" not in claims["sig_ref"]
        ):
            return VerificationResult(
                VerificationStatus.REJECT,
                reason="Step 4: 'sig_ref' must be an object with 'ledger_seq'",
            )
        # segment_id is required for new tokens; v1.0 signed tokens predate this requirement.
        # Warn but do not reject to maintain backward compatibility.
        if "segment_id" not in claims["sig_ref"]:
            warnings.append(
                "Step 4: sig_ref.segment_id is absent. "
                "New token implementations MUST include segment_id. "
                "This token predates SPEC v1.1 and is accepted for backward compatibility."
            )

        # Standard profile optional field validation
        if "schema_v" in claims and claims["schema_v"] != SUPPORTED_SCHEMA_VERSION:
            warnings.append(
                f"Step 4: schema_v={claims['schema_v']} > supported={SUPPORTED_SCHEMA_VERSION}. "
                "Processing known fields only."
            )

        if "boot_id" in claims and not _is_valid_uuid(claims["boot_id"]):
            return VerificationResult(
                VerificationStatus.REJECT,
                reason="Step 4: 'boot_id' is not a valid UUID",
            )

        pstr = _production_validate_token_strings(claims)
        if pstr:
            return VerificationResult(VerificationStatus.REJECT, reason=pstr)
        pint = _production_validate_token_integers(claims)
        if pint:
            return VerificationResult(VerificationStatus.REJECT, reason=pint)

        # ── Step 5: Enforce freshness ─────────────────────────────────────────
        if not skip_freshness:
            now_ms = int(time.time() * 1000)
            age_ms = abs(now_ms - claims["ts"])
            if age_ms > self.freshness_window_ms:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=(
                        f"Step 5: token outside freshness window "
                        f"(age={age_ms}ms, window={self.freshness_window_ms}ms)"
                    ),
                )

        # ── Step 6: Deduplicate ───────────────────────────────────────────────
        dedup_key = (claims["did"], claims["tctx"], claims["event_name"], claims["seq"])
        # Expiry: 2 × freshness window from insertion time (SPEC: "MAY be pruned after
        # 2 × freshnessWindowMs has elapsed since insertion"). Must be insertion-based
        # so static test fixtures with historical ts values don't expire immediately.
        now_ms_dedup = int(time.time() * 1000)
        dedup_expiry_ms = now_ms_dedup + 2 * self.freshness_window_ms
        with self._dedup_lock:
            # Prune expired entries to bound memory growth.
            stale = [k for k, exp in self.dedup_store.items() if exp <= now_ms_dedup]
            for k in stale:
                del self.dedup_store[k]
            if dedup_key in self.dedup_store:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"Step 6: duplicate token (did={claims['did']}, tctx={claims['tctx']}, "
                    f"event_name={claims['event_name']}, seq={claims['seq']})",
                )
            self.dedup_store[dedup_key] = dedup_expiry_ms

        # ── Step 7: Correlate retries ─────────────────────────────────────────
        retry_events = {"payment.retry", "pos.txn.retry", "login.retry", "auth.retry"}
        with self._flow_lock:
            prior = self.flow_store.get(claims["tctx"], [])
            if claims["event_name"] in retry_events and prior:
                max_prior_seq = max(a["seq"] for a in prior)
                if claims["seq"] <= max_prior_seq:
                    return VerificationResult(
                        VerificationStatus.REJECT,
                        reason=(
                            f"Step 7: sequence regression in retry. "
                            f"seq={claims['seq']} <= prior max={max_prior_seq}"
                        ),
                    )
                prior_boot = prior[0].get("boot_id")
                current_boot = claims.get("boot_id")
                if prior_boot and current_boot and prior_boot != current_boot:
                    warnings.append(
                        f"Step 7: boot_id changed mid-flow "
                        f"(prior={prior_boot}, current={current_boot}). "
                        "May indicate device reboot between retries — review policy."
                    )
            self.flow_store.setdefault(claims["tctx"], []).append(claims)

        # ── Step 8: Trust level (requires ledger record fetch in production) ──
        # In this reference implementation we report trust level as SOFTWARE_LAYER
        # unless the caller provides a pre-fetched ledger record. See evaluate_trust().
        trust_level = TrustLevel.SOFTWARE_LAYER
        warnings.append(
            "Step 8: ledger record not fetched. Trust level is software_layer. "
            "Fetch the full Evidence Record via sig_ref.ledger_seq for dispute-grade trust."
        )

        return VerificationResult(
            status=VerificationStatus.VALID,
            claims=claims,
            trust_level=trust_level,
            warnings=warnings,
        )


def evaluate_trust(ledger_record: Dict[str, Any]) -> TrustLevel:
    """
    Evaluate trust level from a fetched Evidence Record.
    Call this after verifying the token and fetching the record from the ledger.
    """
    att = ledger_record.get("attestation_ref")
    if not att:
        return TrustLevel.SOFTWARE_LAYER
    state = att.get("device_state")
    if state == "verified":
        return TrustLevel.HARDWARE_BACKED
    elif state == "hardware_keystore":
        return TrustLevel.HARDWARE_BOUND
    elif state == "unknown":
        return TrustLevel.EXECUTION_PROOF
    elif state == "failed":
        return TrustLevel.COMPROMISED_DEVICE
    return TrustLevel.SOFTWARE_LAYER


# ── Evidence Record verifier ─────────────────────────────────────────────────


class EvidenceRecordVerifier:
    """
    Verifies a device-signed Evidence Record (ledger record).
    Checks signature and optionally validates hash-chain linkage.
    """

    def __init__(self, key_store: KeyStore):
        self.key_store = key_store

    def verify(self, record: Dict[str, Any]) -> VerificationResult:
        """Verify the device signature on a ledger Evidence Record."""
        warnings: List[str] = []

        # Guard against adversarially deep nesting before any json.dumps call.
        try:
            _check_nesting_depth(record)
        except ValueError as exc:
            return VerificationResult(VerificationStatus.REJECT, reason=f"Record structure error: {exc}")

        # Validate ts_source
        ts_source = record.get("ts_source")
        if ts_source is None:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Record missing required 'ts_source' field"
            )
        if ts_source not in VALID_TS_SOURCES:
            warnings.append(
                f"Record ts_source='{ts_source}' is not a recognised value "
                f"({', '.join(sorted(VALID_TS_SOURCES))}). Treat timestamp with caution."
            )

        # M6: validate measured_at on all signals — must not exceed record ts + tolerance
        record_ts = record.get("ts")
        if record_ts is not None:
            for sig_entry in record.get("signals", []):
                measured_at = sig_entry.get("measured_at")
                if measured_at is not None and measured_at > record_ts + SIGNAL_CLOCK_SKEW_TOLERANCE_MS:
                    return VerificationResult(
                        VerificationStatus.REJECT,
                        reason=(
                            f"Record signal '{sig_entry.get('signal', '?')}' has measured_at={measured_at} "
                            f"which exceeds record ts={record_ts} + tolerance={SIGNAL_CLOCK_SKEW_TOLERANCE_MS}ms. "
                            "A signal cannot be measured after the event it is reported with."
                        ),
                    )

        sig_obj = record.get("sig")
        if not sig_obj:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Record missing 'sig' field"
            )

        # S1: reject non-ES256 algo before attempting signature verification
        algo = sig_obj.get("algo")
        if algo != "ES256":
            return VerificationResult(
                VerificationStatus.REJECT,
                reason=f"Record sig.algo must be 'ES256'; got '{algo}'"
            )

        kid = sig_obj.get("key_id")
        if not kid:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Record sig missing 'key_id'"
            )

        public_key = self.key_store.lookup(kid)
        if public_key is None:
            public_key = self.key_store.refetch(kid)
            if public_key is None:
                return VerificationResult(
                    VerificationStatus.REJECT, reason=f"Unknown key_id '{kid}'"
                )
            self.key_store.register(kid, public_key)

        if "value" not in sig_obj:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Record sig missing 'value'"
            )

        # Canonical form: record excluding 'sig', keys sorted
        record_no_sig = {k: v for k, v in record.items() if k != "sig"}
        canonical = json.dumps(
            record_no_sig, sort_keys=True, separators=(",", ":")
        ).encode()

        try:
            raw_sig = _b64url_decode(sig_obj["value"])
            r = int.from_bytes(raw_sig[:32], "big")
            s = int.from_bytes(raw_sig[32:], "big")
            der_sig = encode_dss_signature(r, s)
            public_key.verify(der_sig, canonical, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return VerificationResult(
                VerificationStatus.REJECT, reason="Record signature invalid"
            )
        except Exception as e:
            return VerificationResult(
                VerificationStatus.REJECT, reason=f"Record signature error: {e}"
            )

        return VerificationResult(
            status=VerificationStatus.VALID, trust_level=evaluate_trust(record)
        )

    def verify_chain(self, records: List[Dict[str, Any]]) -> VerificationResult:
        """
        Verify hash-chain integrity across a sequence of Evidence Records.
        Records must be ordered by seq ascending.

        NOTE: This method checks chain integrity only (hash linkage). It does NOT
        verify device signatures on individual records. For full validation callers
        MUST also call verify(record) on each record in the chain.
        """
        if not records:
            return VerificationResult(status=VerificationStatus.VALID)
        records_sorted = sorted(records, key=lambda r: r.get("seq", 0))
        ZEROS64 = "0" * 64
        prev_hash = None
        # Guard each record for deep nesting before json.dumps.
        for record in records_sorted:
            try:
                _check_nesting_depth(record)
            except ValueError as exc:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"Record structure error at seq={record.get('seq')}: {exc}",
                )
        prev_segment_id = None  # type: Optional[int]

        for i, record in enumerate(records_sorted):
            chain_ref = record.get("chain_ref", {})
            seq = record.get("seq")
            hash_algo = chain_ref.get("hash_algo")
            if hash_algo != "sha-256":
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"chain_ref.hash_algo must be 'sha-256'; got '{hash_algo}' at seq={seq}",
                )
            event_hash = chain_ref.get("event_hash")
            stored_prev = chain_ref.get("prev_hash")

            norm_event = _normalize_hex64(event_hash)
            if norm_event is None:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"chain_ref.event_hash must be 64 hexadecimal digits at seq={seq}",
                )
            norm_prev_stored = _normalize_hex64(stored_prev) if stored_prev else None
            if stored_prev is not None and norm_prev_stored is None:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=f"chain_ref.prev_hash must be 64 hexadecimal digits at seq={seq}",
                )

            # S2: First record of each segment MUST carry all-zero prev_hash (SPEC.md §chain_ref).
            # Detected when seq==0 (globally first record) or segment_id increments between records.
            cur_segment_id = chain_ref.get("segment_id")
            is_segment_start = (seq == 0)
            if (cur_segment_id is not None and prev_segment_id is not None
                    and cur_segment_id != prev_segment_id):
                is_segment_start = True
            if is_segment_start and stored_prev is not None and norm_prev_stored != ZEROS64:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=(
                        f"Chain break at seq={seq}: "
                        "first record of segment must have all-zero prev_hash"
                    ),
                )

            # Verify event_hash matches actual record content
            record_no_sig = {k: v for k, v in record.items() if k != "sig"}
            record_for_hash = json.loads(json.dumps(record_no_sig))
            record_for_hash["chain_ref"]["event_hash"] = "0" * 64
            canonical = json.dumps(
                record_for_hash, sort_keys=True, separators=(",", ":")
            ).encode()
            computed_hash = hashlib.sha256(canonical).hexdigest()

            if computed_hash != norm_event:
                return VerificationResult(
                    VerificationStatus.REJECT,
                    reason=(
                        f"Chain break at seq={seq}: "
                        f"event_hash mismatch (stored={(event_hash or '')[:16]}..., "
                        f"computed={computed_hash[:16]}...)"
                    ),
                )

            if prev_hash is not None:
                if norm_prev_stored is None:
                    return VerificationResult(
                        VerificationStatus.REJECT,
                        reason=(
                            f"Chain break at seq={seq}: "
                            "chain_ref.prev_hash missing or not 64 hex digits"
                        ),
                    )
                if norm_prev_stored != prev_hash:
                    return VerificationResult(
                        VerificationStatus.REJECT,
                        reason=(
                            f"Chain break at seq={seq}: "
                            f"prev_hash mismatch (stored={(stored_prev or '')[:16]}..., "
                            f"expected={prev_hash[:16]}...)"
                        ),
                    )

            prev_hash = norm_event
            prev_segment_id = cur_segment_id

        return VerificationResult(status=VerificationStatus.VALID)


# ── CLI ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="YinkoShield Evidence Token Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify a token string directly (skip freshness for static fixtures)
  python verifier.py --token eyJhbGci... --pubkey ../../keys/demo_public_key.pem --skip-freshness

  # Verify from file
  python verifier.py --token-file ../../examples/demo_sequence/01_minimal_profile.jws \\
                     --pubkey ../../keys/demo_public_key.pem --skip-freshness

  # Verify an Evidence Record
  python verifier.py --record ../../examples/full_evidence_record.json \\
                     --pubkey ../../keys/demo_public_key.pem
        """,
    )
    parser.add_argument("--token", help="JWS compact token string")
    parser.add_argument("--token-file", help="Path to .jws file")
    parser.add_argument("--record", help="Path to Evidence Record JSON")
    parser.add_argument("--pubkey", required=True, help="Path to PEM public key")
    parser.add_argument(
        "--kid", default="yinkoshield.device.sign.v1", help="Key ID (kid)"
    )
    parser.add_argument(
        "--skip-freshness",
        action="store_true",
        help="Skip freshness check (use for static demo fixtures)",
    )
    args = parser.parse_args()

    if not args.token and not args.token_file and not args.record:
        parser.print_help()
        sys.exit(1)

    store = KeyStore()
    store.load_pem(args.kid, args.pubkey)

    if args.record:
        with open(args.record) as f:
            record = json.load(f)
        rv = EvidenceRecordVerifier(store)
        result = rv.verify(record)
        print(f"\nEvidence Record verification: {result.status.value.upper()}")
        if result.reason:
            print(f"  Reason: {result.reason}")
        if result.trust_level:
            print(f"  Trust level: {result.trust_level.value}")
        sys.exit(0 if result else 1)

    token = args.token
    if args.token_file:
        with open(args.token_file) as f:
            token = f.read().strip()

    verifier = EvidenceTokenVerifier(store)
    result = verifier.verify(token, skip_freshness=args.skip_freshness)

    print(f"\nToken verification: {result.status.value.upper()}")
    if result.reason:
        print(f"  Reason: {result.reason}")
    if result.claims:
        print(f"  Event:  {result.claims.get('event_name')}")
        print(f"  Device: {result.claims.get('did')}")
        print(f"  seq:    {result.claims.get('seq')}")
        print(f"  tctx:   {result.claims.get('tctx')}")
    if result.trust_level:
        print(f"  Trust level: {result.trust_level.value}")
    if result.warnings:
        for w in result.warnings:
            print(f"  ⚠  {w}")

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
