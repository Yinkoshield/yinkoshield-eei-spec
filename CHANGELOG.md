# Changelog

All notable changes to the YinkoShield Evidence Token Specification are documented here.

This project follows [Semantic Versioning](https://semver.org/). Breaking changes increment the major version; additive changes do not.

---

## [1.0.0] — 2026-03-23

Official first public release.

### Specification (`SPEC.md`)

- Evidence Token format — Minimal Profile (8 fields, ~200 bytes JWS) and Standard Profile (12 fields, ~300 bytes JWS)
- Evidence Record format — full ledger record with context, signals, `chain_ref`, `attestation_ref`, and device signature
- 8-step normative verification pipeline — parse → resolve → verify → validate → freshness → dedup → retry → trust (all steps fail-closed)
- Canonical JSON rules: deep key sort, no whitespace, UTF-8 encoding, null fields included, array insertion order preserved
- Timestamp trust hierarchy (`secure_clock` > `ntp` > `rtc`)
- Signal registry — 5 defined signals: `device.integrity`, `runtime.environment`, `code.integrity`, `binding.status`, `network.identity`
- Event registry — 13 defined events across payment, authentication, and threat categories; normative retry event set
- Key lifecycle, rotation, and retention (180-day minimum dispute window; 18-month scheme-arbitration guidance)
- Trust level model — `hardware_backed` · `hardware_bound` · `execution_proof` · `compromised_device` · `software_layer`
- `did` derivation: SHA-256 of uncompressed EC P-256 point (04 ‖ X ‖ Y, 65 bytes), lowercase hex
- `tctx` format: printable, no whitespace, 96-bit minimum entropy (≥ 24 hex chars of random data)
- `segment_id` required in `sig_ref` for new tokens (backward-compatible with pre-release signed fixtures)
- `event_name` canonical field (legacy `event` accepted during transition; `event_name` takes precedence when both are present)
- `type: authentication` with legacy alias `auth` accepted
- ISO 8583 BER-TLV embedding (DE 48 tag `0xF0`) with annotated byte examples for Minimal and Standard profiles
- Integration profiles: `iso8583-de48-minimal`, `mobile-wallet-retail`, `agent-assisted-channel`
- Privacy profiles: `strict` and `standard`
- Offline operation and freshness policy (event time vs ingress time; `offline_queued` network type)
- Distributed deduplication guidance (SETNX-style pattern, delimiter collision note, `tctx` encoding recommendation)
- Token ↔ Evidence Record binding requirements (`eid`, `did`/`device_id`, `tctx`, `seq`, `sig_ref.ledger_seq`)
- Production implementation limits: JWS compact size (24 KiB), header/payload decoded sizes, header allowlist, string lengths, integer ranges (int53), hex hash validation
- Android attestation trust tier deployment matrix (informative)
- Dispute and liability framing (informative; scheme-complementary)

### Reference implementations

- **Python** ≥ 3.9 — 96 tests, zero runtime dependencies beyond `cryptography`
- **JavaScript** (Node.js ≥ 18) — 87 tests, zero external dependencies
- **Go** ≥ 1.21 — full test suite, zero external dependencies, importable as `github.com/yinkoshield/evidence-verifier-go`
- **Java** ≥ 17 — 53 tests, zero runtime dependencies (JDK stdlib only)

All four implementations enforce:

- JWS header allowlist — reject `jwk`, `x5c`, `x5u`, `crit`, and any unlisted key
- JWS compact, header, and payload byte limits
- String length and integer range (int53) limits on all payload fields
- C1 control character rejection in `tctx` (U+0080–U+009F and invalid UTF-8 bytes)
- Dedup key using NUL-byte (`\x00`) separator to prevent `tctx` collision attacks (Go, JS, Java); Python uses a tuple (inherently safe)
- Dedup TTL based on insertion time (`now + 2 × freshnessWindowMs`) per SPEC "since insertion" wording
- `verifyChain`: all-zero `prev_hash` enforced on first record of each segment (`seq == 0` or `segment_id` increment)
- `verifyChain`: vacuous truth for empty input (VALID — no chain to violate)
- `isValidTctx` (Go): `utf8.ValidString` guard prevents raw C1 bytes from being silently coerced to U+FFFD by range iteration
- `json.dumps` depth guard (Python): `_check_nesting_depth(record, max=32)` before any canonicalization to prevent recursion-based DoS
- `JsonSimple.parseObject` (Java): duplicate key rejection — silently overwriting duplicate keys would allow attacker-controlled disambiguation of security-critical fields such as `alg`
- Thread-safe dedup (`ConcurrentHashMap.putIfAbsent` / mutex) and flow stores (`synchronized` / `RLock`) with correct lock discipline

### Security test vectors

- 3 valid vectors (minimal profile, standard profile, payment retry)
- 20 adversarial vectors across 7 attack categories: `signature_forged`, `algorithm_confusion`, `expired_token`, `replay_attack`, `missing_fields`, `sequence_regression`, `broken_chain`

### Companion documents

- [`CONFORMANCE.md`](CONFORMANCE.md) — operator / certification checklists, CI commands, sign-off template
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — informative STRIDE-oriented threat model and residual risks
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy (GitHub Security Advisories)
- [`AGENTIC_PAYMENT_EXTENSION.md`](AGENTIC_PAYMENT_EXTENSION.md) — forward design note for EEI v2.0 Agentic Profile (non-normative); delegation chain, agent identity claims, scope binding, 11-step pipeline. Same JWS/ES256 format — fully additive, no breaking changes to v1.0 integrations.

### Examples

- Ghost transaction scenario (payment.initiated → payment.retry with shared tctx)
- Chargeback dispute scenario (auth → payment hash chain with attestation evidence)
- Full Evidence Record with signals, attestation_ref, and device signature
- iOS Evidence Record variant
