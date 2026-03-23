# SPEC — Evidence Format

> **Status:** Published · v1.0 · March 2026
> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Design goals

1. **Portable evidence**: minimal claims that can move across systems (gateway, risk engine, scheme, dispute) without requiring full device telemetry.
2. **Measured signals, not verdicts**: evidence reports measurements with provenance; downstream systems own decisioning.
3. **Ordered integrity**: ledger chain provides tamper-evidence for local history.
4. **Low overhead**: header tokens are compact; rich records are optional and async.
5. **Sovereign verification**: no YinkoShield-operated control plane required at verification time — only the operator's registered device public key. Key registration and re-fetch are operator-owned infrastructure.

---

## Two evidence shapes

| Shape | Purpose | Format | When used |
|---|---|---|---|
| Evidence Token | Per-transaction proof, travels with the request | JWS compact | API headers, ISO8583 private fields, message metadata |
| Evidence Record | Full execution context for audit and dispute | JSON (device-signed) | Local ledger, async upload, reconciliation, forensics |

These two shapes are linked: the token carries a `sig_ref` pointer to the corresponding ledger record, which can be fetched when dispute-grade detail is needed.

---

## Core objects

### A) Evidence Token (Header / Compact)

A signed compact token carried with every request. Designed to be present on every call with minimal payload cost — continuous execution provenance at the gateway layer without bloating reverse-billed or constrained-network traffic.

Two token profiles are defined. The **Minimal Profile** is the default. The **Standard Profile** is opt-in for customers who can absorb the additional payload and want richer inline evidence without a ledger fetch.

---

#### Minimal Profile (default)

Eight fields. Approximately 200 bytes as JWS compact. Carries only what the backend cannot derive itself and needs before deciding whether to fetch more.

| Field | Type | Description | Why it's here |
|---|---|---|---|
| `eid` | uuid | Unique evidence id for this token | Links token to ledger record and dispute chain |
| `did` | string | Pseudonymous device id. Derived as SHA-256 of the device's EC P-256 public key in **uncompressed point encoding** (04 ‖ X ‖ Y, 65 bytes, big-endian), lowercase hex-encoded. See [Key management](#key-management) for the canonical derivation. | Identifies the signing device without exposing the public key |
| `kid` | string | Signing key identifier | Required for signature verification |
| `ts` | int | Event timestamp, ms UTC | Enables freshness enforcement and replay prevention |
| `seq` | int | Monotonic ledger sequence number, scoped within boot session | Proves ordering; cannot be faked without breaking the chain. Distinguishes clock skew from tampered sequence |
| `event_name` | string | Event name. Examples: `payment.initiated`, `payment.retry`. See [Event registry](#event-registry) for normative values. | Tells the backend what happened without a ledger fetch; changes immediate processing logic |
| `tctx` | string | Transaction/flow context id, shared across all retries of the same logical transaction. Format: non-empty printable string, no whitespace, minimum 24 hex characters of random data (96 bits minimum entropy). Recommended format: `tctx-` prefix followed by 24+ lowercase hex characters (e.g. `tctx-3e9a1f2b7c4d8e56a0b3c6d9`). Note: test fixture tctx values in this repository use abbreviated formats for readability and do not meet the 96-bit minimum. | Enables deterministic retry correlation and duplicate suppression at the gateway layer |
| `sig_ref` | object | Pointer to the ledger record. Fields: `ledger_seq` (int, required), `segment_id` (int, **required for new tokens**). `sig_ref.ledger_seq` MUST equal the referenced record's `chain_ref.ledger_seq`. | Enables dispute-grade detail fetch without a full device query. `segment_id` is required for new implementations: without it, records cannot be uniquely addressed after ledger compaction or across boot sessions where `seq` resets. **Backward compat:** v1.0 signed tokens predate this requirement and omit `segment_id`. Verifiers MUST NOT reject tokens solely because `segment_id` is absent from `sig_ref`; they SHOULD emit a warning. SDKs generating new tokens MUST include `segment_id`. |

---

#### Standard Profile (opt-in)

Includes all Minimal Profile fields plus the following. Use when the customer can absorb the additional payload and wants richer inline evidence.

| Field | Type | Description |
|---|---|---|
| `schema_v` | int | Token schema version. Current: `1` |
| `boot_id` | uuid | Boot session identifier. Resets on device reboot |
| `scope` | string | Evidence domain. Defined values: `payment`, `login`, `pos.txn`, `authentication`, `threat`. Use `threat` when the token accompanies a threat detection event. Unknown scope values MUST be accepted and treated as opaque strings (forward compatible). |
| `net` | object | Minimal network context: `connected` (bool), `type` (`cellular`, `wifi`, `offline`, `offline_queued`). `offline_queued` indicates the token was generated while offline and queued for delivery. |

---

**Signature (both profiles):**
- Format: **JWS compact** (three base64url-encoded segments: header.payload.signature)
- Algorithm: **ES256 required** (`"alg": "ES256"` in JWS header). Verifiers MUST reject any other value including `"none"`. Algorithm agility is not defined in schema v1; future `alg` values require a `schema_v` increment.
- Signing input: standard JWS signing input (`BASE64URL(header) || '.' || BASE64URL(payload)`)
- **Token payload canonicalization:** Token payload serialization is NOT canonicalized. The signature covers the exact byte sequence produced by the signing SDK. Verifiers MUST NOT re-serialize or sort the payload before verification. This is distinct from Evidence Record canonical JSON — the record requires deep key sorting; the token does not.

**Minimal Profile and schema versioning:** The Minimal Profile does not carry `schema_v`. Minimal Profile tokens are permanently scoped to schema v1 semantics. A Minimal Profile token MUST be processed as schema v1 by any verifier regardless of future schema additions. Integrators requiring later schema versions in inline evidence MUST use the Standard Profile.

**Field naming — `event_name`:** The canonical field name is `event_name` (consistent with the Evidence Record). Pre-release implementations used the shortened field name `event`. Verifiers SHOULD accept both `event_name` and `event` during the transition period; when both are present, `event_name` takes precedence. New token implementations MUST use `event_name`. Existing signed test vectors in this repository use the legacy `event` field name.

**Parsing safety — normative verification order:**

Verifiers MUST process JWS tokens in the following order. Steps fail closed: a failure at any step MUST result in REJECT without proceeding to subsequent steps.

1. **Parse and validate JWS structure:** split the token on `.` into exactly three segments (header, payload, signature). Reject if the count is not three. Base64url-decode and parse the header JSON. Extract `alg` and `kid`. Reject if either is absent. Reject if `alg` is not `ES256` (including `"none"`). _The header is parsed before signature verification to obtain `kid` for key resolution — this is structurally required, not a security exception._
2. **Key resolution:** look up `kid` in the key store. If absent, attempt exactly one re-fetch on a mutually-authenticated channel. Reject if still not found.
3. **Signature verification:** verify the ES256 signature over `BASE64URL(header) || '.' || BASE64URL(payload)` using the resolved public key. Reject on any failure.
4. **Payload decode and field validation:** base64url-decode and parse the payload. Reject if any required field is absent or malformed. Reject if payload `kid` does not match header `kid`.
5. **Freshness:** reject if `ts` is outside the configured freshness window (recommended: ±5 minutes, operator-configurable).
6. **Replay check:** reject if `(did, tctx, event_name, seq)` is present in the dedup store.
7. **Sequence regression (retry events only):** reject if the event is a retry and `seq` is not greater than all prior `seq` values for the same `tctx`.
8. **Trust level resolution:** return trust level from the associated Evidence Record if available; otherwise return `software_layer`.

Additional requirements:
- A cryptographically valid signature on a semantically invalid payload (e.g., missing required fields, malformed `eid`) MUST still result in REJECT.
- Parsers MUST ignore unknown fields. A minimal-profile parser receiving a standard-profile token MUST NOT reject it.
- **Replay protection:** Backends MUST maintain a dedup store keyed on `(did, tctx, event_name, seq)`. Dedup entries MUST be retained for at least the configured freshness window. Entries MAY be pruned after `2 × freshnessWindowMs` has elapsed since insertion — tokens older than the freshness window cannot be replayed regardless, as they are rejected at the freshness check before dedup is consulted.

**Retry event set (normative):**
The following `event_name` values trigger sequence regression checks at verification step 7. Verifiers MUST apply sequence regression enforcement to these events and MUST NOT apply it to any event name not in this list:

| `event_name` | Description |
|---|---|
| `payment.retry` | Retry of a failed or unconfirmed payment |
| `pos.txn.retry` | Retry of a POS transaction |
| `login.retry` | Retry of an authentication flow |
| `auth.retry` | Retry of a generic auth step |

This list is exhaustive for schema v1. Future schema versions may extend it.

---

### B) Evidence Record (Ledger / Rich)

Stored in the on-device ledger. May be uploaded asynchronously. Intended for audit, dispute resolution, reconciliation, and forensic analysis.

#### Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_v` | int | yes | Record schema version. Current: `1` |
| `eid` | uuid | yes | Unique evidence id. Matches the corresponding token's `eid` |
| `device_id` | string | yes | Pseudonymous device id. MUST NOT contain PII. MUST match `did` in the corresponding token. Both are derived identically from the same device public key (SHA-256 of uncompressed EC P-256 point, lowercase hex). **Known naming inconsistency:** the Evidence Record uses `device_id` for this field while the Evidence Token uses `did`. They are the same value. Systems correlating records with tokens MUST compare `record.device_id` with `token.did` explicitly. This inconsistency will be resolved by renaming `device_id` to `did` in a future major schema version. |
| `seq` | int | yes | Monotonic ledger sequence number, scoped within `boot_id` |
| `ts` | int | yes | Event timestamp, ms UTC |
| `ts_source` | enum | yes | Clock source for `ts`. See [Timestamp trust hierarchy](#timestamp-trust-hierarchy) |
| `type` | string | yes | Event group. Enumerated values: `transaction`, `authentication`, `threat`. The value `auth` is accepted as a legacy alias for `authentication` for backward compatibility with pre-release signed records. |
| `event_name` | string | yes | Full event name. Examples: `payment.initiated`, `payment.retry` |
| `tctx` | string | yes | Transaction/flow context id. Same value as the corresponding token `tctx`. Required on all records regardless of `type`. For non-transactional events (`type: threat`) not associated with a specific transaction, implementations SHOULD generate a new unique tctx for that event — it will not match any token tctx and serves as an event-scoped identifier only. |
| `severity` | int | yes | Informational severity level reported by the SDK. Scale: `0` = info, `1` = low, `2` = medium, `3` = high. Reflects SDK assessment of event significance only. Does not imply any enforcement action. Consuming systems MAY use this to prioritise review or alerting; no normative consumer behaviour is defined. Recommended defaults: transaction events → `0`; authentication failure → `1`; threat events: map `confidence: high` → `3`, `medium` → `2`, `low` → `1`, unknown → `2`. |
| `prev_eid` | uuid | recommended | Convenience pointer to the previous event's `eid` in the same flow. SHOULD be omitted on the first event of a segment (do not use empty string — an empty string is not a valid UUID). The security anchor for chain ordering is `chain_ref.prev_hash`, not this field; `prev_eid` aids human-readable traversal only. |

#### `context` object

Bounded device and app context at time of event.

| Field | Type | Required | Description |
|---|---|---|---|
| `app_version` | string | yes | Application version |
| `sdk_version` | string | yes | YinkoShield SDK version |
| `os` | string | yes | OS and version. Format: `platform:version` (e.g. `android:14`, `ios:17`) |
| `boot_id` | uuid | no | Boot session id. Matches token `boot_id` when the Standard Profile token is in use. |
| `uptime_ms` | int | no | Device uptime in milliseconds at time of event. May be unavailable on some platforms. |
| `network.connected` | bool | yes | Whether network was available |
| `network.type` | string | yes | Network type: `cellular`, `wifi`, `offline`, `offline_queued`. Values align with the token `net.type` field. |
| `network.carrier` | string | no | Carrier name. Omit in privacy-sensitive deployments: carrier name combined with MCC/MNC can constitute quasi-identifying information in smaller markets. |
| `sim.present` | bool | yes | Whether a SIM was detected |
| `sim.iccid_hash` | string | no | SHA-256 of ICCID, hex-encoded |
| `sim.mcc` | string | conditional | Mobile Country Code. SHOULD be included when `sim.present = true` and accessible to the SDK. |
| `sim.mnc` | string | conditional | Mobile Network Code. SHOULD be included when `sim.present = true` and accessible to the SDK. |
| `sim.slot` | int | no | SIM slot index. Omit on single-SIM devices or when unavailable. |

When `sim.present = false`, all `sim.*` sub-fields SHOULD be omitted.

#### `signals` array

An array of measured runtime signals. Each entry describes one observation. Evidence reports what was measured — enforcement and decisioning remain with the downstream system.

Each signal entry:

| Field | Type | Description |
|---|---|---|
| `signal` | string | Signal name. See [Signal registry](#signal-registry) |
| `source` | string | Measurement source. See [Signal registry](#signal-registry) |
| `measured_at` | int | Timestamp when this signal was measured, ms UTC. May differ from record `ts` |
| `value` | string | Measured value. See [Signal registry](#signal-registry) for valid values per signal |
| `measurement_method` | enum | How the measurement was produced. Enumerated values: `hardware_attested`, `software_measured`, `heuristic_observed`. Describes mechanism only — verifiers apply their own policy weight |

**Signal staleness:** Signals do not need to be re-measured on every event. A signal measured within the current boot session may be carried forward if it remains valid. Implementations should re-measure signals on boot, on significant state changes, or when `measured_at` age exceeds the configured staleness threshold (recommended: 60 seconds for high-frequency signals, 300 seconds for boot-state signals).

**`measured_at` constraint:** A signal MUST NOT be measured after the event it is reported with. Verifiers MUST reject records containing any signal where `measured_at` exceeds the record's `ts` by more than the configured clock-skew tolerance (recommended: 5 000 ms). A signal dated in the future relative to the event timestamp indicates either a clock error or data fabrication.

#### `detail` object

The `detail` object is **optional**. A record without `detail` is valid and complete. Its presence and schema vary by `event_name`. Recommended fields for transaction events:

| Field | Type | Description |
|---|---|---|
| `txn_ref` | string | Transaction reference from the application layer |
| `txn_type` | string | Transaction type (e.g. `payment`, `reversal`) |
| `outcome` | string | Execution outcome at time of record (e.g. `initiated`, `retry`, `confirmed`) |
| `retry_count` | int | Number of retries for this `tctx`. `0` on first attempt |
| `error_code` | string\|null | Error code if applicable |

Recommended fields for **authentication events** (`type: authentication`):

| Field | Type | Description |
|---|---|---|
| `auth_method` | string | Authentication method: `biometric`, `pin`, `otp`, `pattern` |
| `outcome` | string | Execution outcome: `confirmed`, `failed`, `timeout` |
| `retry_count` | int | Number of auth retries for this flow. `0` on first attempt |
| `error_code` | string\|null | Error code if applicable |

Recommended fields for **threat events** (`type: threat`):

| Field | Type | Description |
|---|---|---|
| `threat_type` | string | Threat category: `root_detection`, `emulator_detection`, `tamper_detection`, `replay_attempt`, `unknown` |
| `indicator` | string | Human-readable description of the observed indicator |
| `confidence` | string | Confidence level of the detection: `high`, `medium`, `low` |

#### `chain_ref` object

Hash-chain linkage for tamper-evidence of the local ledger.

| Field | Type | Description |
|---|---|---|
| `hash_algo` | string | Hash algorithm used. MUST be `sha-256` in schema v1. Verifiers MUST reject any record where `hash_algo` is absent or not `sha-256`. |
| `event_hash` | string | SHA-256 of this record's canonical JSON representation (before `sig` is appended), hex-encoded |
| `prev_hash` | string | `event_hash` of the previous ledger record in the same segment. MUST be all zeros (`"000...000"`, 64 hex characters) on the first record of each segment — i.e., when `segment_id` was just assigned (either the very first record ever, or the first record after `segment_id` incremented due to ledger compaction or rotation). |
| `segment_id` | int | Ledger segment identifier. Increments on ledger compaction or rotation |
| `ledger_seq` | int | Matches the record's top-level `seq` |

Normative limits on hex string length, allowed characters, and case handling when comparing or linking hashes appear under **Production implementation requirements** (this document).

#### `attestation_ref` object (optional)

Platform attestation reference, when available. Evidence is valid without attestation; its presence strengthens the trust domain.

| Field | Type | Description |
|---|---|---|
| `provider` | string | Attestation provider. Examples: `android_keystore`, `tpm2`, `platform_quote` |
| `quote_id` | string | Reference to the attestation quote |
| `pcr_digest` | string | PCR digest or equivalent platform measurement |
| `device_state` | enum | Platform-reported device state. Values: `verified`, `hardware_keystore`, `unknown`, `failed`. Note: `hardware_keystore` describes the platform mechanism (a hardware-backed key store without a full TEE attestation certificate chain); the resulting *trust level* is the distinct value `hardware_bound`. |

**Trust degradation model:**

| Attestation present | `device_state` | Trust level | Basis |
|---|---|---|---|
| Yes | `verified` | `hardware_backed` | TEE with full key attestation certificate chain |
| Yes | `hardware_keystore` | `hardware_bound` | Hardware Keystore, non-exportable key, no TEE attestation certificate |
| Yes | `unknown` | `execution_proof` | Execution proof; platform integrity state indeterminate |
| Yes | `failed` | `compromised_device` | Evidence recorded; device integrity compromised |
| No | — | `software_layer` | Software-layer evidence only; no platform binding |

Downstream systems MUST apply policy based on the declared trust level. YinkoShield does not enforce; it reports. Trust level is a declared property of the evidence and is never inferred by the consuming system.

#### `sig` object

Device signature over the record.

| Field | Type | Description |
|---|---|---|
| `algo` | string | Signature algorithm. MUST be `ES256`. Verifiers MUST reject any record where `sig.algo` is absent or not `ES256`, including `"none"`. |
| `key_id` | string | Signing key identifier. Matches `kid` in the corresponding token |
| `value` | string | **base64url-encoded** (RFC 4648 §5, no padding) ES256 signature over the canonical record (excluding the `sig` field itself) |

---

## Timestamp trust hierarchy

The `ts_source` field indicates the reliability of the event timestamp.

| Value | Description | Dispute weight |
|---|---|---|
| `secure_clock` | Hardware-backed secure clock or TEE-attested time | Highest |
| `ntp` | Network time, recently synchronised | Medium |
| `rtc` | Device RTC only, no network sync | Lowest |

Verifiers processing Evidence Records MUST validate `ts_source` against the defined enum values above. An unrecognised value SHOULD generate a warning and the record MAY still be accepted; a missing `ts_source` MUST cause rejection. Verifiers SHOULD apply appropriate scepticism to records with `ts_source: rtc` in dispute contexts, particularly where timestamp ordering matters.

---

## Signal registry

Defined signal names, sources, and valid values. Implementations must use these values. Unknown signal names should be ignored by verifiers (forward compatibility).

| `signal` | `source` | Valid `value` | `measurement_method` | Description |
|---|---|---|---|---|
| `device.integrity` | `bootloader` | `verified`, `unknown`, `failed` | `hardware_attested` | Platform boot integrity state |
| `runtime.environment` | `attestation` | `native_hardware`, `emulator`, `unknown` | `hardware_attested` | Execution environment type |
| `code.integrity` | `signature_check` | `valid`, `invalid`, `unknown` | `software_measured` | App code signature verification |
| `binding.status` | `keystore` | `bound`, `unbound`, `unknown` | `hardware_attested` \| `software_measured` | Whether the signing key is bound to this device's hardware. Use `hardware_attested` when the keystore provides a hardware attestation certificate (e.g., Android StrongBox / KeyAttestation); use `software_measured` when hardware attestation is unavailable and binding is verified by software inspection only. |
| `network.identity` | `sim_observer` | `stable`, `changed`, `absent` | `heuristic_observed` | SIM/network identity continuity since last boot |

Additional signals may be defined in future schema versions. Verifiers MUST ignore unrecognised signal names.

**Signal staleness thresholds:**

| Signal | Category | Recommended re-measurement threshold |
|---|---|---|
| `device.integrity` | Boot-state | 300 seconds |
| `runtime.environment` | Boot-state | 300 seconds |
| `code.integrity` | Boot-state | 300 seconds |
| `binding.status` | Boot-state | 300 seconds |
| `network.identity` | High-frequency (SIM swap detection) | 60 seconds |

---

## Event registry

The following event names are defined for schema v1. Implementations MUST use these names for the described events. Unknown event names received by a verifier MUST be accepted (forward compatible).

| Event name | `type` | Description |
|---|---|---|
| `payment.initiated` | `transaction` | First attempt to submit a payment |
| `payment.retry` | `transaction` | Retry of an unconfirmed payment (same `tctx`) |
| `payment.confirmed` | `transaction` | Payment confirmation received from backend |
| `payment.failed` | `transaction` | Payment attempt failed with an error |
| `pos.txn.initiated` | `transaction` | POS transaction initiated |
| `pos.txn.retry` | `transaction` | POS transaction retry |
| `pos.txn.confirmed` | `transaction` | POS transaction confirmed |
| `login.initiated` | `authentication` | Authentication flow started |
| `login.retry` | `authentication` | Authentication flow retried |
| `login.confirmed` | `authentication` | Authentication confirmed |
| `auth.biometric.confirmed` | `authentication` | Biometric authentication step confirmed |
| `auth.retry` | `authentication` | Generic auth step retried |
| `threat.detected` | `threat` | Runtime threat signal observed |

This list is exhaustive for schema v1. The `event_name` field in both the token and the record MUST use these names where applicable. New events in future schema versions MUST use the `domain[.subdomain].verb` naming pattern (e.g., `payment.initiated`, `auth.biometric.confirmed`, `pos.txn.retry`).

---

## Canonical JSON

Evidence Record signatures and `chain_ref.event_hash` values are computed over a **canonical JSON** representation of the record. Implementations must produce identical byte sequences to interoperate.

**Rules (normative):**

1. Serialise the record as JSON with **no insignificant whitespace** — no spaces, no newlines between tokens.
2. Sort all object keys **lexicographically** (Unicode code-point order, ascending) at **every depth level**. This is a recursive deep sort: nested objects must also have their keys sorted.
3. Use UTF-8 encoding.
4. Exclude the `sig` field before serialising (the `sig` field is never part of the signed material).
5. **Null-valued fields MUST be included** in the canonical serialisation. A field present in the signed record with a `null` value MUST appear in the canonical JSON output (e.g., `"error_code":null`). Omitting null fields produces a different byte sequence and will cause signature verification to fail. Implementations MUST NOT strip null fields before signing or hashing.
6. **Array elements preserve insertion order.** Only object keys are sorted. Array elements (e.g., entries in the `signals` array) MUST NOT be reordered — their position is part of the signed byte sequence.

**For `chain_ref.event_hash` specifically:** before hashing, zero the `event_hash` field itself to the 64-character hex string `"0000000000000000000000000000000000000000000000000000000000000000"`, then serialise and SHA-256 hash the result. This breaks the circular dependency between the record content and its own hash.

**Reference:**
The canonical form is equivalent to Python `json.dumps(record, sort_keys=True, separators=(',', ':'))` encoded as UTF-8. The reference implementations include test vectors that can be used to validate canonical JSON output.

---

## Key management

### Key lifecycle

- The device signing key (EC P-256 recommended) is generated on-device during SDK initialisation.
- Where available, the key is generated inside a TEE, Keystore, or TPM and is non-exportable.
- ECDSA signing operations MUST use a CSPRNG or RFC 6979 deterministic nonce (k) generation. A biased nonce exposes the private key after a small number of signatures.
- The corresponding public key is registered with the backend during device onboarding. The backend stores a mapping of `kid` → public key. The registration channel MUST be integrity-protected (e.g., TLS with certificate pinning). The specific registration protocol is operator-defined; YinkoShield's Zero Trust Bootstrap Protocol (ZTBP) is one recommended approach and is not mandatory.
- `kid` is a stable, opaque identifier for the key. Recommended format: `{did}.sign.v{n}` where `did` is the device id derived from the public key and `n` is the key generation counter. Example: `b262eacf9d58d9f3...a46e6.sign.v1`. Using `did` as the prefix ensures `kid` is globally unique and directly traceable to the signing key without a separate lookup table.
- **`did` derivation:** The `did` field is derived as SHA-256 of the device's EC P-256 public key in **uncompressed point encoding** (04 ‖ X ‖ Y, 65 bytes, big-endian), lowercase hex-encoded. This derivation is deterministic and produces a consistent value regardless of key storage format. A canonical test vector is provided in `test-vectors/did-derivation/test_vector.json`. Note: signed test fixtures in this repository use a legacy placeholder format (`dev-{identifier}`) that predates this specification.

### Key rotation

- Rotation is triggered by: app reinstall, explicit SDK rotation call, or operator policy (e.g. time-based).
- On rotation, the SDK generates a new key pair and registers the new public key with the backend via the onboarding/key-update endpoint.
- The old `kid` remains valid for verification of historical records and tokens signed before rotation. Backends MUST retain public keys for the duration of the dispute window (operator-defined; minimum: 180 days). Operators SHOULD align key retention with their applicable dispute resolution timeline; under major payment scheme rules, arbitration disputes may extend to 18 months from the original transaction date. To revoke a compromised key before the dispute window expires, the operator removes the `kid` mapping from the key store; tokens signed with that key will then fail at step 2 (key resolution) of the verification pipeline.
- Post-rotation, new tokens and records carry the new `kid`. Verifiers encountering an unknown `kid` SHOULD treat it as a re-registration event and attempt exactly one re-fetch of the key mapping. The key re-fetch MUST be performed over a mutually-authenticated, integrity-protected channel (e.g., mTLS with the operator backend); an unauthenticated re-fetch endpoint allows substitution of a malicious public key, undermining signature verification. If the re-fetch returns no key, the token MUST be rejected. Verifiers MUST NOT retry within the same verification call.

---

## Versioning and compatibility

- `schema_v` increments on breaking changes (field removals or type changes).
- Additive changes (new optional fields) do not increment `schema_v`.
- Parsers MUST ignore unknown fields (forward compatible).
- Header token claims SHOULD be kept stable across versions. New claims are always optional.
- When a parser encounters a `schema_v` higher than it supports, it SHOULD process known fields and flag the unknown version for review rather than rejecting outright.

---

## ISO 8583 embedding

The Evidence Token (Minimal Profile, ~200 bytes as UTF-8) embeds in a private data element of an ISO 8583 message. YinkoShield Evidence Tokens are message-type agnostic; inclusion in specific MTIs (e.g., MTI 0100 authorization request, MTI 0200 financial transaction) is at the discretion of the integrator and applicable scheme rules.

### Field selection

| Priority | Field | Condition |
|---|---|---|
| 1 | DE 48 (Additional Data — Private Use) | Preferred. Theoretical maximum: 999 bytes (LLLVAR). Actual supported capacity varies by acquirer, processor, and network variant — many implementations impose limits of 200–512 bytes. Implementers MUST confirm supported DE 48 capacity with their acquirer and processor before deployment. |
| 2 | DE 124 / DE 125 | Fallback if DE 48 capacity is exhausted by co-resident subelements. Coordinate with scheme and acquirer. |

### BER-TLV structure within DE 48

When DE 48 is already in use, encapsulate the Evidence Token in a BER-TLV envelope using tag `0xF0` (private class, constructed — does not conflict with any defined Mastercard or Visa subelement range):

| Tag | Length | Value |
|---|---|---|
| `0x01` | 1 byte | Format version — `0x01` for this specification |
| `0x02` | 1 byte | Profile indicator — `0x01` Minimal Profile, `0x02` Standard Profile |
| `0x03` | variable | JWS compact token — ASCII-encoded bytes |

Length encoding follows BER-TLV: single byte for lengths ≤ `0x7F`; two bytes with `0x81` prefix for lengths `0x80`–`0xFF`; three bytes with `0x82` prefix for lengths `0x100`–`0xFFFF`. The outer `0xF0` container length covers all three sub-TLVs.

**Annotated example — Minimal Profile (~216 bytes total in DE 48):**
```
F0 81 D5        -- outer TLV: tag 0xF0, length 213 bytes
  01 01 01      -- sub-tag 0x01: version = 0x01  (3 bytes)
  02 01 01      -- sub-tag 0x02: profile = Minimal (3 bytes)
  03 81 CC      -- sub-tag 0x03: JWS token, 204 bytes (3 + 204 = 207 bytes)
  65 79 4A ...  -- JWS compact bytes (eyJhb...)
```
Inner content: 3 + 3 + 207 = 213 bytes (0xD5). Total in DE 48: 1 (tag) + 2 (0x81 D5 length) + 213 = 216 bytes.

**Annotated example — Standard Profile (~330 bytes total in DE 48):**
```
F0 82 01 46     -- outer TLV: tag 0xF0, length 326 bytes
  01 01 01      -- sub-tag 0x01: version = 0x01  (3 bytes)
  02 01 02      -- sub-tag 0x02: profile = Standard (3 bytes)
  03 82 01 3C   -- sub-tag 0x03: JWS token, 316 bytes (4 + 316 = 320 bytes)
  65 79 4A ...  -- JWS compact bytes
```
Inner content: 3 + 3 + 320 = 326 bytes (0x0146). Total in DE 48: 1 (tag) + 3 (0x82 01 46 length) + 326 = 330 bytes.

If DE 48 is not already in use, the `0xF0` wrapper is optional; the JWS token MAY occupy the field directly with the profile indicator conveyed in the JWS header `typ` extension. In this case, the JWS header SHOULD carry a `typ` value to identify the evidence profile:

| Profile | Recommended `typ` value |
|---|---|
| Minimal Profile | `yks-eei+jwt; profile=minimal` |
| Standard Profile | `yks-eei+jwt; profile=standard` |

Verifiers receiving a bare DE 48 token MUST NOT require a `typ` value for successful verification — it is informational. When `typ` is present, verifiers MAY use it for routing or logging but MUST NOT apply algorithm constraints based on it.

### Reversals (MTI 0400 / MTI 0420)

Reversal messages do not require a new Evidence Token — the original execution history is available via the Local Evidence Ledger using the original `tctx`. Implementations SHOULD include the original `eid` from the authorization Evidence Token in the reversal message DE 48 for convenient correlation during dispute reconstruction. Auto-generated reversals (e.g., system-initiated MTI 0420 after acquirer timeout) where the original `eid` is unavailable MAY omit this field; in such cases `tctx` remains the primary correlation key.

---

## Production implementation requirements

The following requirements apply to **verifiers** and **hardened SDK / gateway parsers** deployed in production. They limit abuse (oversized inputs, algorithm confusion via header injection, JSON interoperability bugs) and align token verification with fetched Evidence Records. Reference implementations in this repository enforce these rules.

### JWS compact token limits

| Rule | Requirement |
|------|-------------|
| Maximum UTF-8 size of the full compact JWS string | **24 576 bytes (24 KiB)** — reject larger inputs before decoding. |
| Maximum size of Base64url-decoded **header** JSON | **2 048 bytes** — reject before or immediately after decode. |
| Maximum size of Base64url-decoded **payload** JSON | **12 288 bytes (12 KiB)** — reject before or immediately after decode. |

### JWS header allowlist (fail closed)

To mitigate header-based confusion attacks (`jwk`, `x5u`, `crit`, etc.), verifiers MUST reject tokens whose decoded JWS header contains **any** key that is **not** in this set:

| Key | Requirement |
|-----|-------------|
| `alg` | REQUIRED. MUST be the string `ES256`. |
| `kid` | REQUIRED. MUST be a string (see length limits below). |
| `typ` | OPTIONAL. If present, MUST be a string (recommended: `JWT` or `JWS` or the `yks-eei+jwt` forms in [ISO 8583 embedding](#iso-8583-embedding)); maximum length **128** Unicode code points. |

All other header parameters MUST cause **REJECT** (including `jwk`, `x5c`, `x5u`, `crit`, duplicated semantics, or vendor extensions). Evidence Tokens do not use embedded keys in the JWS header; keys are always resolved from the operator key store by `kid`.

### String and claim length limits (token payload)

After JSON parsing, verifiers MUST reject payloads where any of the following exceed the limit (Unicode code points / string `.length` as applicable):

| Field | Maximum length |
|-------|----------------|
| `kid` | 256 |
| `did` | 128 |
| `tctx` | 256 |
| `event_name` | 128 |

The `eid` and `boot_id` (if present) MUST remain valid UUID strings (36 ASCII characters in standard form) as already required elsewhere.

### Integer ranges (token payload and JSON interoperability)

All of the following MUST hold; otherwise the verifier MUST **REJECT**:

| Field | Rule |
|-------|------|
| `ts`, `seq` | MUST be integers (not boolean). MUST be ≥ **0**. MUST be ≤ **9 007 199 254 740 991** (2⁵³ − 1) so values are safe in IEEE-754 double and ECMAScript `Number` without rounding. |
| `ts` | SHOULD be ≥ **1 000 000 000 000** ms epoch (~2001-09-09 UTC) unless the operator explicitly configures a lower bound for legacy data. |
| `sig_ref.ledger_seq` | MUST be an integer ≥ 0 and ≤ 2⁵³ − 1. |
| `sig_ref.segment_id` | If present, MUST be an integer ≥ 0 and ≤ 2⁵³ − 1. |

### `chain_ref` hexadecimal hashes (Evidence Record)

`chain_ref.event_hash` and `chain_ref.prev_hash` MUST each be **exactly 64** hexadecimal digits (`0-9`, `a-f` or `A-F`). Producers SHOULD emit **lowercase** hex. Verifiers MUST **normalise** case to lowercase when **comparing** computed vs stored hashes or when comparing `prev_hash` linkage across records, so uppercase hex in historical data does not break verification.

### Token ↔ Evidence Record binding (full validation)

When an operator has verified an Evidence Token **and** retrieved the Evidence Record identified by `sig_ref` (and device ledger APIs), the following equalities MUST hold before treating the pair as cryptographically bound for dispute or policy decisions. Mismatch MUST result in **REJECT** (or equivalent failure) for that combined validation:

| Token field | Record field |
|-------------|----------------|
| `eid` | `eid` |
| `did` | `device_id` |
| `tctx` | `tctx` |
| `seq` | `seq` |
| `sig_ref.ledger_seq` | `chain_ref.ledger_seq` |

If both token and record carry `sig_ref.segment_id` and `chain_ref.segment_id`, they MUST be equal. If one side omits `segment_id`, binding checks MUST NOT fail solely for omission (backward compatibility); operators MAY apply separate policy for missing `segment_id`.

Binding checks are **in addition to** verifying the JWS signature on the token and the device signature on the record, and **in addition to** optional `verify_chain` hash linkage across records.

### Canonical JSON and Unicode

Evidence Record canonicalisation (signing and `event_hash`) uses UTF-8 JSON with no insignificant whitespace, deep-sorted object keys, and **preserved array order**, as specified in [Canonical JSON](#canonical-json). Implementations MUST:

- Emit **only** UTF-8; reject records that are not valid UTF-8 when ingested as bytes.
- Not apply Unicode normalization to object keys or string values during canonicalisation unless a future schema version explicitly defines it (schema v1 does **not**).

### Key re-fetch and verification availability

Key re-fetch (Step 2) MUST use a **mutually authenticated, integrity-protected** channel as already required. Production deployments SHOULD:

- Apply **timeouts** and **bounded retries** on re-fetch appropriate to latency SLOs (exact values are operator-defined).
- **Cache** successfully fetched keys for a bounded TTL to reduce load; **negative cache** unknown `kid` briefly to mitigate denial-of-service storms (policy is operator-defined).

### Distributed deduplication (Step 6)

The deduplication store keyed by `(did, tctx, event_name, seq)` MUST be **shared** across all verifier instances that accept traffic for the same population; otherwise replays may succeed at a different node. The store MUST support **atomic insert** semantics for the dedup key (e.g. `SETNX` or equivalent). Entry retention MUST remain at least the configured freshness window as already specified.

**Reference pattern (informative):** Many deployments map the dedup key to a single atomic operation: insert-if-absent with a TTL at least the configured freshness window (and MAY extend to `2 × freshnessWindowMs` per pruning guidance in [Core objects](#core-objects)). Example key layout: `eei:dedup:{did}:{tctx}:{event_name}:{seq}` where each component is encoded to avoid delimiter collisions inside `tctx` (e.g. length-prefix, hashing, or a structured binary key). The reference Go and JavaScript verifiers concatenate with `:` — operators using that pattern MUST ensure `tctx` cannot contain the separator or MUST use a collision-safe encoding. The Python reference uses a tuple key (no string collision class). Implementations MAY correlate gateway **idempotency keys** with the same dedup key for HTTP-level retries.

---

## Integration profiles (informative, operator-defined)

These profiles help banks, schemes, and large merchants align on **minimum evidence** without replacing scheme authentication (e.g. 3-D Secure) or network rules. A profile selects token shape, recommended events, and DE 48 packaging expectations. **Normative crypto and verification rules** elsewhere in this document are unchanged; profiles are **deployment contracts** between operators.

### Profile: `iso8583-de48-minimal`

| Aspect | Requirement |
|--------|-------------|
| Token | **Minimal Profile** JWS unless acquirer capacity allows Standard Profile. |
| DE 48 | When used, follow [ISO 8583 embedding](#iso-8583-embedding) BER-TLV `0xF0` wrapper where co-resident subelements require it. |
| Evidence Record | MUST be retrievable for dispute path when `sig_ref` is present; [binding](#token--evidence-record-binding-full-validation) SHOULD be applied when records are fetched. |
| `event_name` | MUST include at least one lifecycle event for the payment attempt (e.g. `payment.initiated` per [Event registry](#event-registry)); additional events RECOMMENDED for retries (`payment.retry`) and failures where product policy requires them. |
| Offline | When the device queues work offline, Standard Profile `net.type` SHOULD be `offline_queued` where the token carries network context. |

### Profile: `mobile-wallet-retail`

| Aspect | Requirement |
|--------|-------------|
| Token | **Standard Profile** RECOMMENDED when bandwidth and DE 48 (or API) capacity allow; otherwise Minimal with ledger fetch for detail. |
| `boot_id` | RECOMMENDED for session-scoped debugging across fragmented Android estates. |
| `signals` | MAY include `device.integrity`, `binding.status`, `runtime.environment` where the platform exposes measurements (see [Signal registry](#signal-registry)). |
| Trust | Operators SHOULD document how `attestation_ref.device_state` maps to risk policy; weak tiers MUST NOT be presented as hardware-backed attestation. |

### Profile: `agent-assisted-channel`

| Aspect | Requirement |
|--------|-------------|
| Events | Operators SHOULD define **distinct** `event_name` values for **customer confirmation** vs **agent actions** under the [Event registry](#event-registry) naming pattern (`domain[.subdomain].verb`), and register them in program documentation. |
| `tctx` | MUST remain stable across all steps of the same assisted transaction (same correlation rules as retries). |
| Records | RECOMMENDED: `context` fields that identify **assisted** vs **self-service** mode without PII (boolean or coarse enum only). |

### Android attestation and trust tiers (informative)

Fragmented Android estates often lack uniform TEE-backed attestation. Operators SHOULD use this matrix for **honest** risk policy and customer messaging. Normative enum values and trust mapping are in the Evidence Record **`attestation_ref`** section above.

| Typical capability | `device_state` (record) | Resulting trust tier | Programme note |
|--------------------|-------------------------|----------------------|----------------|
| Full key attestation / TEE certificate chain | `verified` | `hardware_backed` | Strongest device binding in schema v1 |
| Hardware Keystore, non-exportable key, no full attestation chain | `hardware_keystore` | `hardware_bound` | Common on mainstream Android |
| Attestation missing, failed, or OEM implementation unreliable | `unknown` | `execution_proof` | Typical for many devices; MUST NOT be marketed as smart-card–grade |
| Integrity checks report compromise | `failed` | `compromised_device` | Audit trail preserved; separate policy decides whether to decline the payment |

Producers MUST NOT set `device_state` to `verified` unless the platform meets the definition of `verified` in this specification.

---

## Offline operation, device time, and freshness policy

Disconnected or high-latency networks (common in mobile retail) require explicit operator policy; the spec defines **integrity artifacts**, not **when** a gateway accepts them.

### Event time vs arrival time

- Producers SHOULD set token `ts` to the **ms epoch when the event occurred** on the device (or as close as the secure clock allows), not solely the time of HTTP submission.
- When events are **queued offline** and sent in a batch, each token SHOULD still carry the **original** event `ts`; gateways MAY record separate **ingress timestamps** for operations (outside the signed token).

### Freshness when `offline_queued` is used

- Verifiers apply [freshness](#core-objects) using `ts` unless the operator configures otherwise.
- Operators MAY define a **secondary policy** (e.g. accept if **submission time** is within window while flagging **stale `ts`**) for queued traffic. Such policy MUST be **documented and audited**; it weakens replay detection tied to wall-clock age of the event. Reference verifiers in this repository use **`ts` only** for freshness unless extended by the deployer.

### Clock trust

Evidence Records carry `ts_source` ([Timestamp trust hierarchy](#timestamp-trust-hierarchy)). Verifiers SHOULD treat `rtc` or unknown sources with appropriate risk weighting in downstream fraud engines. EEI does not replace **NTP** or **secure clock** provisioning on the device.

---

## Disputes, investigations, and liability (informative)

EEI strengthens **integrity and portability** of device-reported execution evidence. It does **not** by itself assign **chargeback liability**, **SCA outcome**, or **scheme compliance** — those remain under **network rules**, **issuer policy**, and **law**.

| Evidence state | Typical investigative use | Does **not** establish |
|----------------|---------------------------|-------------------------|
| Valid JWS + registered key | Cryptographic proof that **this device key** signed **this payload** at **`ts`** in **`tctx`** | That the cardholder **intended** the payment, or was not coerced |
| Token + Record + [binding](#token--evidence-record-binding-full-validation) | Consistent narrative between inline token and ledger row | Merchant **fulfillment** or **goods received** |
| `verify_chain` OK (hash linkage) | Tamper-evidence for **presented** ledger segment | That the **first** record in the world is genesis (partial chains are valid by verifier design) |
| Trust `hardware_backed` / `hardware_bound` | Stronger platform binding when attestation/keystore is genuine | Absence of **malware** or **root** if signals were not measured |

**Scheme-facing recommendation:** Acquirers and wallets SHOULD map EEI event sets to **internal reason codes** and **dispute playbooks** explicitly. Payment networks provide **existing** dispute and authentication data elements; EEI is **complementary evidence**, not a substitute for **CAVV / 3DS results** unless a program **explicitly** says so.

---

## Conformance and certification (informative)

### Reference test material

| Asset | Purpose |
|-------|---------|
| `test-vectors/valid/` | Positive JWS fixtures |
| `test-vectors/invalid/` | Negative cases (forged sig, replay, missing fields, etc.) |
| `examples/` | Signed records and demo chains |
| `verifiers/python`, `javascript`, `go`, `java` | Executable checks against the same vectors and crafted cases |

### Minimum producer checklist (pre-production)

Operators certifying an SDK or gateway integration SHOULD verify:

1. **Crypto:** ES256 JWS; signing input is standard compact JWS; no payload re-canonicalisation by verifiers.
2. **Production limits:** [JWS limits](#jws-compact-token-limits), [header allowlist](#jws-header-allowlist-fail-closed), string and integer bounds enforced at verify time.
3. **Dedup:** Shared store with **atomic insert** for `(did, tctx, event_name, seq)` across all verifier instances; TTL ≥ freshness window.
4. **Keys:** `kid` registration, rotation, and retention for at least the **dispute window** ([Key management](#key-management)); re-fetch **mutually authenticated**.
5. **Binding:** When records are fetched, [token ↔ record binding](#token--evidence-record-binding-full-validation) applied before treating evidence as unified.
6. **Privacy:** Apply a [privacy profile](#privacy-profiles-for-data-minimisation) appropriate to jurisdiction.

### Reference verifier suites

CI SHOULD run: `verifiers/python` (`pytest tests/test_verifier.py`), `verifiers/javascript` (`node --test tests/test_verifier.test.js`), `verifiers/go` (`go test ./...`), `verifiers/java` (`mvn test`). Passing all four is a **necessary** cross-language consistency check for this repository; it is **not** a substitute for **penetration testing** or **formal verification** of a production deployment.

---

## Privacy and data minimisation

### Privacy profiles for data minimisation

Operators SHOULD select one of the following **privacy profiles** for each deployment region or product line. Fields not listed remain governed by the bullet rules below.

| Profile | `context.network` / `carrier` / `mcc` / `mnc` / `iccid_hash` | `signals` |
|---------|----------------------------------------------------------------|-----------|
| **strict** | Omit `carrier`, `mcc`, `mnc`, and `iccid_hash` unless a written DPIA requires them; minimise `context.network` to coarse `connected` / `type` only where possible | Omit quasi-identifying telemetry unless required for fraud policy |
| **standard** | Optional per [Signal registry](#signal-registry) and record schema; follow local law on telecom identifiers | Full signal registry optional fields allowed |

**strict** is RECOMMENDED for high-privacy jurisdictions or small markets where `carrier` + `mcc` + `mnc` may be quasi-identifying.

- No customer PII in any evidence field (no names, phone numbers, email addresses, account numbers).
- Device identifiers MUST be pseudonymous. Derived from the device public key, not from hardware serial numbers or advertising IDs.
- `iccid_hash` MUST be a one-way hash (SHA-256) of the raw ICCID. The raw ICCID MUST NOT appear in evidence.
- `carrier` is optional and SHOULD be omitted in privacy-sensitive deployments. The combination of `carrier`, `mcc`, and `mnc` may constitute quasi-identifying information in smaller markets.
- Evidence records are local-first. Retrieval via the YinkoShield forensic channel is operator-initiated and event-targeted; records are retrieved individually by reference, not bulk-synchronised by default. Operators who retrieve Evidence Records become responsible for those records under applicable data protection law and MUST apply their data retention and erasure policies accordingly.
- Asynchronous upload should be governed by operator data handling policy.

---

## Companion documents (informative)

The following files support procurement, certification, and security review. They are **informative**; if anything conflicts with the body of this specification, **this document (`SPEC.md`) prevails**.

| Document | Purpose |
|----------|---------|
| [`CONFORMANCE.md`](CONFORMANCE.md) | Verifier and producer checklists, CI commands, integration profile sign-off template. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | STRIDE-oriented threats, residual risks, and suggested review questions. |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting scope and process (not normative for token format). |

---

## Version history

| Version | Date | Summary |
|---|---|---|
| v1.0 | March 2026 | First published specification. Evidence Token (Minimal and Standard profiles) and Evidence Record formats. 8-step normative verification pipeline (fail-closed). Canonical JSON. Signal and event registries. Key lifecycle, rotation, and 180-day retention. Trust level model (`hardware_backed`, `hardware_bound`, `execution_proof`, `compromised_device`, `software_layer`). ISO 8583 BER-TLV embedding (DE 48 tag `0xF0`). Integration profiles (`iso8583-de48-minimal`, `mobile-wallet-retail`, `agent-assisted-channel`). Privacy profiles. Distributed dedup guidance. Production implementation limits. |
