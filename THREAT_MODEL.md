# YinkoShield EEI — Threat model (informative)

**Status:** Informative companion to [`SPEC.md`](SPEC.md) v1.2.  
**Purpose:** Support security architecture review, procurement Q&A, and gap analysis. It is **not** a formal pen-test report.

---

## 1. Scope and assumptions

**In scope**

- Evidence **Token** (JWS compact) and **Evidence Record** (device-signed JSON ledger row).
- Verifier behaviour as specified (parse → key → signature → claims → freshness → dedup → retry → trust).
- Operator infrastructure: key store, dedup store, optional ledger fetch.

**Assumptions**

- Verifiers use **only** operator-registered public keys (no trust in unsigned header key material).
- Attackers may control **network**, **other users’ devices** (not the victim’s signing key, unless compromised), and **malformed inputs**.
- Scheme authentication (e.g. 3-D Secure) and network cryptography are **orthogonal** unless explicitly combined in your program.

---

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Device **private signing key** | Forges tokens/records if extracted. |
| **Key store** (`kid` → public key) | Wrong key → acceptance of forged signatures. |
| **Dedup store** | Weak dedup → replay of valid tokens. |
| **Ledger records** | Tampering breaks integrity unless signatures + chain hold. |
| **Evidence semantics** | `event_name`, `tctx`, `seq` drive risk and dispute narrative. |

---

## 3. STRIDE-oriented analysis

| Threat | Example | Mitigation in EEI design | Residual risk |
|--------|---------|---------------------------|---------------|
| **Spoofing** | Attacker presents another device’s identity | `did` / `kid` bound to registered key; verifier resolves key from **your** store | **Enrollment fraud**: attacker registers their own device legitimately and then abuses flows. |
| **Spoofing** | Malicious key substitution | Re-fetch MUST be **mutually authenticated**; unauthenticated refetch forbidden | Misconfigured gateway trusts open endpoint. |
| **Tampering** | Alter token payload post-signing | ES256 over exact signing input; verifiers do not “fix up” payload | None if crypto correct. |
| **Tampering** | Alter ledger record | Record signature over canonical JSON; `chain_ref` links rows | **Partial chain**: verifier does not prove global genesis — by design; see `SPEC.md`. |
| **Repudiation** | User denies payment | Signed evidence under device key supports **non-repudiation of the claim**, not **intent** or **coercion** | Social engineering, family/device sharing. |
| **Repudiation** | Merchant denies SDK behaviour | Consistent token + bound record + chain | Requires **fetching** record and **binding** check in your process. |
| **Information disclosure** | PII in evidence | `SPEC.md` forbids PII; privacy profiles | **Quasi-IDs** (`carrier`, `mcc`, `mnc`) in small markets — use **strict** profile. |
| **Denial of service** | Huge JWS, slow JSON | Production **size limits**, **header allowlist** | Application-level floods — rate limits out of spec. |
| **Denial of service** | Dedup / key lookup storms | **Negative cache** for unknown `kid`; bounded refetch | Misconfiguration / missing cache. |
| **Elevation of privilege** | Algorithm confusion (`HS256`, `none`) | **ES256 only**; header allowlist | New algorithms need **schema** bump — don’t ad-hoc extend. |

---

## 4. Implementation pitfalls (seen in real deployments)

| Pitfall | Impact |
|---------|--------|
| **Per-process dedup** only | Replay succeeds on another node. |
| **String dedup key** with `:` inside `tctx` | Possible collision class (Go/JS concatenation); use safe encoding or tuple semantics. |
| **Freshness on submission time** without policy doc | Hides stale event replay class; document trade-off (`SPEC.md` offline section). |
| **Marketing `hardware_backed`** on `unknown` devices | Overclaims assurance; regulatory / dispute backlash. |
| **Skipping binding** when record exists | Token and record can be **mixed** from different flows if IDs collide across bugs. |

---

## 5. What EEI does **not** prove

- That the **cardholder intended** the transaction (coercion, scam).
- That the **merchant** shipped goods or services.
- That the device is **free of malware** unless integrity **signals** and policy say so.
- That **3DS** or **SCA** succeeded — unless your program **links** those outcomes to EEI events explicitly.

---

## 6. Recommended review questions (for your boss / scheme partner)

1. Who can **register** keys, and how is **account takeover** at enrollment detected?
2. Is dedup **shared and atomic** across all verifier instances?
3. Is **ledger fetch + binding** mandatory for dispute path, or only token verification?
4. Which **integration profile** and **privacy profile** apply per region?
5. What **trust tier** is acceptable for **high-value** or **regulated** flows?

---

## 7. Related documents

- **[`SPEC.md`](SPEC.md)** — normative format and verification rules.  
- **[`CONFORMANCE.md`](CONFORMANCE.md)** — certification-style checklists and CI commands.  
- **[`SECURITY.md`](SECURITY.md)** — vulnerability reporting process.
