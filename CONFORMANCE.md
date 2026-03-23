# YinkoShield EEI — Conformance & certification guide

**Audience:** acquirers, retail banks, gateways, wallet vendors, internal security / architecture review.  
**Normative source:** [`SPEC.md`](SPEC.md) (v1.0). This document is **informative**; where it disagrees with `SPEC.md`, **SPEC.md wins**.

---

## 1. What “conformance” means here

| Layer | Conformance statement |
|-------|------------------------|
| **Format** | Tokens and records match field types, signing rules, and canonical JSON (records) defined in `SPEC.md`. |
| **Verification** | A verifier implements the **8-step** pipeline **fail-closed** and, for production deployments, the **Production implementation requirements** in `SPEC.md`. |
| **Operations** | The operator runs **shared atomic dedup**, **authenticated key lifecycle**, and **documented** offline/freshness policy where relevant. |

Passing reference CI **proves cross-language parity of the reference code**, not that your production deployment is secure.

---

## 2. Verifier conformance checklist

A **conformant verifier** (gateway, risk service, issuer adapter) SHOULD demonstrate:

1. **JWS:** Three segments; base64url; header `alg` = `ES256`, `kid` present; signature over `header_b64.payload_b64`.
2. **Key resolution:** Lookup `kid`; at most one **mutually authenticated** re-fetch if unknown; reject if still missing.
3. **Claims:** Required minimal fields; header `kid` = payload `kid`; `tctx` rules; UUID rules for `eid` / optional `boot_id`; `sig_ref.ledger_seq`; legacy `event` normalisation per spec.
4. **Freshness:** Configurable window; reject outside window unless operator policy explicitly extends (document risk).
5. **Dedup:** Key `(did, tctx, event_name, seq)` with **atomic insert** across all instances; retention ≥ freshness window. The reference implementations use in-memory stores — these are **not sufficient for production**. Multi-instance deployments MUST use a shared atomic store (e.g. Redis `SETNX` with TTL = 2 × freshness window) to prevent replay across nodes.
6. **Retry events:** Sequence regression only for the **normative retry set** in `SPEC.md`.
7. **Production limits:** JWS UTF-8 size, decoded header/payload caps, **header allowlist** (`alg`, `kid`, optional `typ`), string and integer bounds, optional `ts` floor per operator policy.
8. **Records (if implemented):** ES256 over canonical JSON; `chain_ref.hash_algo` = `sha-256`; hex length and case normalisation on compare; `ts_source` and signal `measured_at` rules per spec.
9. **Binding (when records fetched):** Apply **Token ↔ Evidence Record binding** from `SPEC.md` (Production implementation requirements — binding subsection), or an equivalent check, before treating token+record as one logical evidence unit.

**Reference implementations:** `verifiers/python`, `verifiers/javascript`, `verifiers/go`, `verifiers/java`.

---

## 3. Producer (SDK / device) conformance checklist

A **conformant producer** SHOULD demonstrate:

1. **Keys:** EC P-256; non-exportable where platform allows; safe ECDSA nonce usage (CSPRNG or RFC 6979).
2. **Registration:** Public key → operator with **integrity-protected** channel; stable `kid`; retention policy aligned to **dispute window** (see `SPEC.md` Key management). Minimum enrollment security bar: (a) **mutual TLS** between device and operator backend; (b) **challenge-response binding** — the device signs an operator-issued nonce with the EEI key to prove possession at enrollment time; (c) the platform **Key Attestation certificate chain** (Android Keystore / iOS SE attestation) MUST be captured and stored alongside the `kid` to establish hardware-backed provenance. Deployments that cannot meet (c) MUST document the trust degradation and reflect it in `device_state`.
3. **Tokens:** Minimal or Standard profile per chosen [integration profile](SPEC.md#integration-profiles-informative-operator-defined); `segment_id` in `sig_ref` for new implementations.
4. **Records:** Canonical JSON for signing; correct `event_hash` computation; `ts_source` populated honestly.
5. **Offline:** Original event `ts` preserved when queuing; `net.type` / `offline_queued` when applicable.
6. **Privacy:** A chosen **privacy profile** (`strict` or `standard`) per `SPEC.md`. Deployments serving **South African consumers** (POPIA scope) MUST use the `strict` profile — `device_id` MUST be pseudonymised or omitted, and `tctx` MUST NOT be linkable to a natural person without explicit consent. Consumer-facing flows MUST NOT log raw `(device_id, tctx)` pairs without a documented lawful processing basis under POPIA §11.
7. **Attestation:** `device_state` values that **match reality** (see Android matrix in `SPEC.md`); never claim `verified` without meeting the spec definition.

---

## 4. Reference test material (minimum bar)

| Asset | Use |
|-------|-----|
| `test-vectors/valid/` | Positive JWS verification |
| `test-vectors/invalid/` | Negative cases across attack categories |
| `examples/` | Signed records, demo chains, dispute scenarios |
| Four verifier test suites | Language parity and regression |

---

## 5. CI commands (repository health)

Run from a clone of this repo:

```bash
cd verifiers/python && python3 -m pytest tests/test_verifier.py -q
cd verifiers/javascript && node --test tests/test_verifier.test.js
cd verifiers/go && go test ./... -count=1
cd verifiers/java && mvn test -q
```

**Recommended:** integrate the same commands (or vendored copies of the verifiers) into your own CI when you fork or embed the reference code.

---

## 6. Integration profile selection

Declare which profile you implement (see `SPEC.md`):

- `iso8583-de48-minimal` — card rails, tight DE 48 budget.
- `mobile-wallet-retail` — richer Standard profile when bandwidth allows.
- `agent-assisted-channel` — distinct events for customer vs agent steps.

Document deviations in your integration security addendum.

---

## 7. Sign-off template (internal use)

| Item | Owner | Evidence (link / ticket) |
|------|--------|----------------------------|
| Verifier checklist (§2) | | |
| Producer checklist (§3) | | |
| Dedup: shared store + atomic insert | | |
| Key lifecycle + refetch auth | | |
| Freshness + offline policy documented | | |
| Privacy profile selected | | |
| Threat model reviewed ([`THREAT_MODEL.md`](THREAT_MODEL.md)) | | |

---

## 8. What this guide does **not** replace

- Payment **scheme** certification, **PCI DSS**, or **legal** admissibility of evidence in a given jurisdiction.
- Penetration testing, code review, or formal verification of your **production** codebase.
- Mapping EEI artifacts to **chargeback reason codes** or **3DS** outcomes — see `SPEC.md` disputes section; that mapping is **program-specific**.

For threat analysis, see **[`THREAT_MODEL.md`](THREAT_MODEL.md)**. For reporting vulnerabilities in this repository, see **[`SECURITY.md`](SECURITY.md)**.
