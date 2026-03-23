# Security policy

## Supported versions

Security fixes are applied to the **latest published** specification and reference verifiers on the default branch of this repository. Integrators who **vendor** older commits should track upstream and merge fixes.

## Reporting a vulnerability

**Please do not** open a public GitHub issue for undisclosed security vulnerabilities.

1. Use **[GitHub Security Advisories](https://github.com/yinkoshield/yinkoshield-eei-spec/security/advisories/new)** for this repository (preferred), **or**
2. Contact the maintainers through the **security contact** published on the [YinkoShield](https://github.com/yinkoshield) organisation or project website, if different from this repo.

Include:

- A short description of the issue and its impact  
- Affected component (e.g. `verifiers/python`, `SPEC.md` normative text)  
- Steps to reproduce or a proof-of-concept, if possible  

We aim to acknowledge reports within a **few business days**. Disclosure timeline will be coordinated with the reporter.

## Scope (in scope)

- Reference verifiers under `verifiers/` (Python, JavaScript, Go, Java)  
- Normative text in `SPEC.md` that affects verification or parsing safety  
- Example scripts and docs that could mislead integrators into unsafe patterns  

## Out of scope

- **The demo private key** (`keys/demo_private_key.pem`) is **intentionally public** for test vectors and examples. It must **never** be used in production; see [`keys/README.md`](keys/README.md).  
- Issues in **forks** or **downstream products** that have diverged from this repository (report to those maintainers).  
- **General support** or integration questions (use regular issues or discussions).  

## Hardening reminders for integrators

- Run your own **penetration testing** and **dependency audits** on any forked verifier code.  
- Follow [`CONFORMANCE.md`](CONFORMANCE.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for deployment checklists and residual risks.  

---

Copyright © 2025-2026 Yinkozi Group — YinkoShield 
