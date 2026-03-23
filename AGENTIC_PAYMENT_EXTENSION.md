# YinkoShield EEI — Agentic Payment Extension (Design Note)

> **Status:** Draft · v0.1 · March 2026
> **Type:** Forward design note — not normative. This document describes the intended direction for EEI v2.0 Agentic Profile. It does not modify `SPEC.md` (v1.0). When a normative version is ratified, it will supersede this note and be incorporated into `SPEC.md`.

---

## 1. Motivation

EEI v1.0 was designed for a **human-initiated transaction model**: a person interacts with a device, the device SDK produces an Evidence Token, and that token travels with the payment request. The signing key is bound to the device; the `did` uniquely identifies the device; the `tctx` identifies the logical transaction; the `seq` provides ordering within a boot session.

Agentic payment introduces a structurally different execution model:

| Dimension | Human-initiated (v1.0) | Agentic (v2.0 target) |
|-----------|------------------------|------------------------|
| Who initiates | Human via UI | Autonomous agent (AI or rule-based) on behalf of a human |
| Signing key | Device-bound, hardware-backed | Agent key (may be software, HSM, or delegated) |
| Identity chain | Device → Operator | Human principal → Delegating agent → Executing agent → Device |
| Confirmation | Implicit (human present) | Explicit (human pre-authorised scope) or fully autonomous |
| Evidence anchor | Device attestation | Delegation credential + optional device attestation |
| Dedup scope | Per device, per tctx | Per agent, per delegation grant, per tctx |

Without an extension, an agentic actor could either:

- **Replay a human's token** — the token carries no claim about who triggered the payment, so an agent acting outside its mandate is indistinguishable from a human-initiated flow.
- **Issue tokens without a delegation credential** — a compromised or rogue agent can sign arbitrary tokens with no audit trail of the authorisation chain.
- **Circumvent human-confirmation requirements** — high-value or sensitive payment categories may require explicit human confirmation; v1.0 provides no field for an agent to prove this occurred.

---

## 2. Design goals

1. **Delegation auditability** — every agentic token must carry a verifiable chain from the human principal to the executing agent and the specific grant that authorised the payment.
2. **Scope binding** — the delegation grant MUST explicitly enumerate the permitted payment categories, counterparties, amount range, and time window. A token issued outside the grant scope MUST be rejected.
3. **Human-confirmation binding** — tokens for confirmation-required categories MUST carry a signed confirmation reference (hardware-backed where the platform allows) that a human explicitly approved the transaction.
4. **Agent identity** — the executing agent MUST be identified by a verifiable identifier. Agent keys SHOULD be hardware-backed (HSM) or otherwise isolated from the application layer.
5. **Backward compatibility** — v1.0 tokens MUST continue to verify unchanged. Agentic tokens are identified by the presence of the new `agent` claim block.
6. **Sovereign model preserved** — no YinkoShield-operated infrastructure. Delegation registry, grant issuance, and agent key management are all operator-owned.

---

## 3. New claims: `agent` block

The Agentic Profile extends the Standard Profile (v1.0) by adding an `agent` object to the token payload. All sub-fields within `agent` are normative when the block is present. A token carrying `agent` MUST be processed by the Agentic Profile verification pipeline (§5); a verifier that does not implement the Agentic Profile MUST reject such tokens.

```json
"agent": {
  "aid":        "<agent-id>",
  "akid":       "<agent-key-id>",
  "grant_ref":  "<grant-id>",
  "grant_hash": "<sha-256-hex>",
  "chain_depth": 1,
  "confirmation": {
    "type":    "human_explicit",
    "ref":     "<confirmation-token-id>",
    "method":  "biometric"
  }
}
```

### 3.1 Field definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `aid` | string | **REQUIRED** | Agent identifier. Derived identically to `did` (SHA-256 of the agent's uncompressed EC P-256 public key, lowercase hex), or an operator-assigned URN for non-key-identified agents. |
| `akid` | string | **REQUIRED** | Agent signing key identifier, registered in the operator's agent key store. The token signature is verified against the key identified by `akid`. When `akid` is present in the `agent` block, it takes precedence over the top-level `kid` for signature verification. The top-level `kid` MUST still be present and MUST identify the device key that co-signed or anchored the evidence (if a device is in the flow); if no device is in the flow, `kid` MUST equal `akid`. |
| `grant_ref` | string | **REQUIRED** | Stable identifier of the delegation grant that authorises this agent to initiate payments on behalf of the principal. The grant is resolved from the operator's grant registry. |
| `grant_hash` | string | **REQUIRED** | SHA-256 of the canonical JSON serialisation of the grant document (same canonical rules as Evidence Records). Verifiers MUST compute and compare this hash after resolving the grant; mismatch MUST cause REJECT. |
| `chain_depth` | int | **REQUIRED** | Number of delegation hops from the human principal to the executing agent. Value `1` means the principal directly delegated to this agent. Maximum value: `4`. Verifiers MUST reject tokens where `chain_depth` exceeds the operator's configured maximum. |
| `confirmation` | object | **CONDITIONAL** | Present when the payment category or amount requires human confirmation. See §3.2. |

### 3.2 Confirmation sub-object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | **REQUIRED** | One of: `human_explicit` (human confirmed this specific transaction), `human_pre_authorised` (human pre-authorised a batch or standing order matching this transaction), `autonomous` (no human confirmation; permitted only for grant-scoped autonomous categories). |
| `ref` | string | **REQUIRED** | Identifier of the confirmation record. For `human_explicit`: the confirmation token ID (a separate short-lived JWS signed by the device with the human's biometric prompt). For `human_pre_authorised`: the standing-order or batch authorisation reference. For `autonomous`: the grant sub-scope reference that permits autonomous execution. |
| `method` | string | OPTIONAL | Confirmation method. Defined values: `biometric`, `pin`, `passkey`, `push_approval`, `pre_authorised`, `none`. Verifiers MAY use this field for step-up authentication decisions. |

---

## 4. Delegation grant document

The grant is an operator-managed document stored in the operator's grant registry. The `grant_hash` in the token pins the exact grant version that was in force when the token was issued.

```json
{
  "grant_id":   "<stable-grant-id>",
  "version":    1,
  "principal":  "<did-of-human-principal>",
  "agent":      "<aid-of-executing-agent>",
  "issued_at":  1742000000000,
  "expires_at": 1742086400000,
  "scope": {
    "event_names":    ["payment.initiated", "payment.retry"],
    "amount_max_zar": 50000,
    "counterparties": ["merchant-id-a", "merchant-id-b"],
    "autonomous_permitted": false,
    "confirmation_required_above_zar": 10000
  },
  "chain": [
    { "delegator": "<did-of-principal>", "delegatee": "<aid-of-agent>", "depth": 1 }
  ]
}
```

Canonical JSON rules (deep key sort, no whitespace, UTF-8, null fields included) apply to the grant document for hash computation, identical to Evidence Records.

---

## 5. Agentic Profile verification pipeline

The Agentic Profile extends the 8-step v1.0 pipeline with three additional steps. All existing steps remain unchanged and fail-closed.

```
Step 1   Parse            (unchanged)
Step 2   Key resolution   (extended: resolve akid from agent key store if agent block present)
Step 3   Signature        (unchanged; verifies against resolved key)
Step 4   Claims           (extended: validate agent block fields; reject if chain_depth > max)
Step 5   Freshness        (unchanged)
Step 6   Dedup            (extended: dedup key includes aid and grant_ref — see §5.1)
Step 7   Retry            (unchanged)
Step 8   Trust            (unchanged)
──────────────────────────────────────────────────────────────────────────
Step 9   Grant resolution Resolve grant by grant_ref from operator registry.
                          Compute SHA-256 of canonical grant JSON.
                          Compare with grant_hash in token. REJECT on mismatch.
Step 10  Scope check      Verify event_name ∈ grant.scope.event_names.
                          Verify payment amount ≤ grant.scope.amount_max_zar (if available).
                          Verify counterparty ∈ grant.scope.counterparties (if enumerated).
                          Verify grant.expires_at > token ts. REJECT if expired.
                          REJECT if grant revoked (operator revocation check).
Step 11  Confirmation     If event requires human confirmation (per operator policy or
                          grant.scope.confirmation_required_above_zar), verify:
                          - agent.confirmation.type ≠ autonomous
                          - agent.confirmation.ref resolves to a valid confirmation record
                          - confirmation record ts within configurable window of token ts
                          - confirmation record signed by device key (kid) for human_explicit
                          REJECT if any confirmation requirement is unmet.
```

Steps 9–11 are fail-closed. A verifier that encounters an `agent` block but does not implement steps 9–11 MUST reject the token.

### 5.1 Agentic dedup key

The v1.0 dedup key `(did, tctx, event_name, seq)` is insufficient for agentic flows because the same `(did, tctx)` may appear under multiple agents acting for the same device (e.g. a device-local agent and a cloud agent both attempting the same payment).

Agentic dedup key:

```
<did> NUL <aid> NUL <grant_ref> NUL <tctx> NUL <event_name> NUL <seq>
```

All separator rules from v1.0 (NUL-byte `\x00`, no colons) apply. TTL remains `now + 2 × freshnessWindowMs` (insertion-based).

---

## 6. Trust level model extension

The v1.0 trust levels (`hardware_backed`, `hardware_bound`, `execution_proof`, `compromised_device`, `software_layer`) describe device-side evidence quality. Agentic tokens introduce a second dimension: **delegation trust**.

| Delegation trust level | Meaning |
|------------------------|---------|
| `grant_hardware_bound` | Grant signed by an HSM-backed agent key; Key Attestation certificate chain captured at agent enrollment |
| `grant_software_bound` | Grant signed by a software agent key; key material isolated but not hardware-backed |
| `grant_unbound` | Grant present but agent key provenance unknown or not captured at enrollment |
| `grant_absent` | No `agent` block; human-initiated flow (v1.0 semantics) |

Verifiers SHOULD surface the delegation trust level alongside the device trust level in their result objects to allow downstream risk decisioning.

---

## 7. Security considerations

### 7.1 Grant replay

An attacker who captures a valid grant document and a legitimate token could attempt to forge new tokens with a different `tctx` but the same `grant_ref` and `grant_hash`. Mitigation: the token signature covers the full payload including `tctx`, `ts`, and `seq` — a forged token requires access to the agent signing key. The grant hash alone is not sufficient.

### 7.2 Delegation chain inflation

An attacker may attempt to register a long delegation chain (`chain_depth = 4`) to obscure the true principal. Operators MUST configure a maximum `chain_depth` appropriate to their use case and MUST resolve and validate every hop in the chain array before accepting the token.

### 7.3 Confirmation token reuse

A `human_explicit` confirmation token issued for one payment MUST NOT be accepted for a different payment. The confirmation record MUST bind the `tctx` and `eid` of the transaction it confirms. Verifiers MUST reject confirmation references where the bound `tctx` does not match the token's `tctx`.

### 7.4 Autonomous scope creep

Grants with `autonomous_permitted: true` are the highest-risk category. Operators MUST enforce narrow `event_names` and tight `amount_max_zar` limits on autonomous-permitted grants. Grants SHOULD have short `expires_at` windows (recommendation: ≤ 24 hours) and MUST be revocable in real time.

### 7.5 Agent key enrollment

Agent key enrollment follows the same minimum bar as device key enrollment (CONFORMANCE.md §3 item 2): mTLS, challenge-response possession proof, and Key Attestation certificate chain (HSM attestation where available). A compromised agent key allows issuance of arbitrary agentic tokens for all grants associated with that agent.

---

## 8. Privacy considerations

An `aid` in the token payload creates a new correlation vector: `(did, aid, grant_ref)` can link a human's device to a specific agent and authorisation grant. Under POPIA (and equivalent privacy frameworks), operators MUST:

- Treat `aid` as personal information when it is linkable to a natural person.
- Apply the `strict` privacy profile or its agentic equivalent for South African consumer deployments.
- Not persist raw `(did, aid, tctx)` triples beyond the dedup retention window without a documented lawful basis.

---

## 9. Backward compatibility

| Token type | agent block | Pipeline |
|------------|-------------|----------|
| v1.0 Minimal | absent | 8-step v1.0 (unchanged) |
| v1.0 Standard | absent | 8-step v1.0 (unchanged) |
| v2.0 Agentic | present | 8-step v1.0 + steps 9–11 |

A v2.0 verifier MUST handle both token types. A v1.0 verifier encountering a token with an `agent` block MUST reject it (unknown claim block in a fail-closed pipeline).

---

## 10. Open questions (items to resolve before normative publication)

1. **Multi-hop chain validation**: Should the verifier resolve and validate every intermediate delegation hop, or only the terminal grant? Full chain validation provides stronger auditability but increases latency.

2. **Offline agentic tokens**: Can an agent issue tokens while offline? The v1.0 offline model preserves original `ts` and sets `net.type = offline_queued`. For agentic tokens, the grant expiry check (Step 10) requires a live grant registry fetch. Define behaviour when the grant registry is unreachable.

3. **Confirmation token format**: Should the `human_explicit` confirmation token be a full EEI token (JWS, ES256, device-signed) or a lighter format? A full EEI token provides the strongest binding but doubles the payload size for high-value transactions.

4. **Agent key rotation**: How should `akid` rotation interact with in-flight tokens? Define a key overlap window analogous to the v1.0 device key retention policy.

5. **Scheme interoperability**: How does the `agent` block map to ISO 8583 DE 48 embedding? Define a sub-tag allocation (suggest `0xF1`) in the ISO 8583 integration profile.

---

## 11. Relationship to existing documents

| Document | Interaction |
|----------|-------------|
| `SPEC.md` v1.0 | This note extends; does not modify. |
| `CONFORMANCE.md` | §3 item 2 (enrollment) and §2 item 5 (dedup) apply directly to agentic enrollment and agentic dedup respectively. |
| `THREAT_MODEL.md` | New threat categories: delegation grant forgery, autonomous scope creep, confirmation bypass. These will be added to THREAT_MODEL.md when this extension reaches normative status. |
| `CHANGELOG.md` | Entry to be added as `[2.0.0]` upon ratification. |
