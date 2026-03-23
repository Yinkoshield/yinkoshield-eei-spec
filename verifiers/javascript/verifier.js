// Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
//
// YinkoShield Execution Evidence Infrastructure
// Evidence Token Verifier — JavaScript Reference Implementation
//
// This is a reference implementation of the verification pipeline defined in SPEC.md.
// It demonstrates sovereign verification: no YinkoShield infrastructure required.
// Verification uses only the registered device public key.
//
// https://github.com/yinkoshield
/**
 * YinkoShield Evidence Token Verifier — JavaScript Reference Implementation
 *
 * Implements the 8-step verification pipeline defined in SPEC.md.
 * Works in Node.js (>=18) using the built-in `crypto` module — no external dependencies.
 *
 * Usage:
 *   node verifier.js --token <jws_string> --pubkey <path_to_public_key.pem> [--skip-freshness]
 *   node verifier.js --token-file <path_to.jws> --pubkey <path_to_public_key.pem> [--skip-freshness]
 *   node verifier.js --record <path_to_record.json> --pubkey <path_to_public_key.pem>
 *
 * No YinkoShield infrastructure required. Verification uses only the registered device public key.
 */

'use strict';

const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

// ── Constants ─────────────────────────────────────────────────────────────────

const SUPPORTED_SCHEMA_VERSION  = 1;
const DEFAULT_FRESHNESS_WINDOW_MS = 300_000; // 5 minutes
// Canonical field is 'event_name'; legacy 'event' accepted for backward compat. Checked separately.
const REQUIRED_MINIMAL_FIELDS   = new Set(['eid', 'did', 'kid', 'ts', 'seq', 'tctx', 'sig_ref']);
const VALID_ALGORITHMS          = new Set(['ES256']);

// ── Result types ──────────────────────────────────────────────────────────────

const TrustLevel = Object.freeze({
  HARDWARE_BACKED:    'hardware_backed',
  HARDWARE_BOUND:     'hardware_bound',
  EXECUTION_PROOF:    'execution_proof',
  COMPROMISED_DEVICE: 'compromised_device',
  SOFTWARE_LAYER:     'software_layer',
});

const VALID_TS_SOURCES = new Set(['secure_clock', 'ntp', 'rtc']);
const SIGNAL_CLOCK_SKEW_TOLERANCE_MS = 5_000; // max ms a signal's measured_at may exceed record ts

// Production limits — SPEC.md "Production implementation requirements"
const MAX_JWS_COMPACT_UTF8_BYTES = 24_576;
const MAX_JWS_HEADER_DECODED_BYTES = 2_048;
const MAX_JWS_PAYLOAD_DECODED_BYTES = 12_288;
const ALLOWED_JWS_HEADER_KEYS = new Set(['alg', 'kid', 'typ']);
const MAX_HEADER_TYP_LENGTH = 128;
const MAX_CLAIM_KID_LENGTH = 256;
const MAX_CLAIM_DID_LENGTH = 128;
const MAX_CLAIM_TCTX_LENGTH = 256;
const MAX_CLAIM_EVENT_NAME_LENGTH = 128;
const MAX_JSON_SAFE_INTEGER = Number.MAX_SAFE_INTEGER; // 2**53 - 1
const MIN_TS_MS_RECOMMENDED = 1_000_000_000_000;

const VerificationStatus = Object.freeze({
  VALID:   'valid',
  REJECT:  'reject',
});

class VerificationResult {
  constructor({ status, reason = null, claims = null, trustLevel = null, warnings = [] }) {
    this.status     = status;
    this.reason     = reason;
    this.claims     = claims;
    this.trustLevel = trustLevel;
    this.warnings   = warnings;
  }
  get ok() { return this.status === VerificationStatus.VALID; }
}

function reject(reason) {
  return new VerificationResult({ status: VerificationStatus.REJECT, reason });
}
function valid(claims, trustLevel, warnings = []) {
  return new VerificationResult({ status: VerificationStatus.VALID, claims, trustLevel, warnings });
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function isValidUuid(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s));
}

/** @returns {string|null} lowercase hex or null */
function normalizeHex64(value) {
  if (typeof value !== 'string' || value.length !== 64) return null;
  const lowered = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(lowered)) return null;
  return lowered;
}

function validateJwsHeaderProduction(jwsHeader) {
  const keys = Object.keys(jwsHeader);
  const bad = keys.filter(k => !ALLOWED_JWS_HEADER_KEYS.has(k));
  if (bad.length) return `Step 1: disallowed JWS header key(s): ${bad.sort().join(', ')}`;
  if (typeof jwsHeader.alg !== 'string') return "Step 1: JWS header 'alg' must be a string";
  if (typeof jwsHeader.kid !== 'string') return "Step 1: JWS header 'kid' must be a string";
  if ('typ' in jwsHeader) {
    if (typeof jwsHeader.typ !== 'string') return "Step 1: JWS header 'typ' must be a string";
    if (jwsHeader.typ.length > MAX_HEADER_TYP_LENGTH) {
      return `Step 1: JWS header 'typ' exceeds max length ${MAX_HEADER_TYP_LENGTH}`;
    }
  }
  return null;
}

function validateTokenStringsProduction(claims) {
  if (typeof claims.kid === 'string' && claims.kid.length > MAX_CLAIM_KID_LENGTH) {
    return `Step 4: 'kid' exceeds max length ${MAX_CLAIM_KID_LENGTH}`;
  }
  if (typeof claims.did === 'string' && claims.did.length > MAX_CLAIM_DID_LENGTH) {
    return `Step 4: 'did' exceeds max length ${MAX_CLAIM_DID_LENGTH}`;
  }
  if (typeof claims.tctx === 'string' && claims.tctx.length > MAX_CLAIM_TCTX_LENGTH) {
    return `Step 4: 'tctx' exceeds max length ${MAX_CLAIM_TCTX_LENGTH}`;
  }
  if (typeof claims.event_name === 'string' && claims.event_name.length > MAX_CLAIM_EVENT_NAME_LENGTH) {
    return `Step 4: 'event_name' exceeds max length ${MAX_CLAIM_EVENT_NAME_LENGTH}`;
  }
  return null;
}

function validateTokenIntegersProduction(claims) {
  function check(name, v) {
    if (typeof v !== 'number' || !Number.isInteger(v)) return `Step 4: '${name}' must be an integer`;
    if (v < 0 || v > MAX_JSON_SAFE_INTEGER) {
      return `Step 4: '${name}' out of allowed range [0, ${MAX_JSON_SAFE_INTEGER}]`;
    }
    return null;
  }
  let err = check('ts', claims.ts);
  if (err) return err;
  err = check('seq', claims.seq);
  if (err) return err;
  if (claims.ts < MIN_TS_MS_RECOMMENDED) {
    return `Step 4: 'ts' is below minimum allowed (${MIN_TS_MS_RECOMMENDED} ms epoch)`;
  }
  err = check('sig_ref.ledger_seq', claims.sig_ref.ledger_seq);
  if (err) return err;
  if ('segment_id' in claims.sig_ref) {
    err = check('sig_ref.segment_id', claims.sig_ref.segment_id);
    if (err) return err;
  }
  return null;
}

/**
 * Validate token ↔ record field equality (SPEC — Production implementation requirements).
 * @returns {string|null} rejection reason or null if OK
 */
function verifyTokenRecordBinding(claims, record) {
  if (claims.eid !== record.eid) return 'Binding: token eid does not match record eid';
  if (claims.did !== record.device_id) return 'Binding: token did does not match record device_id';
  if (claims.tctx !== record.tctx) return 'Binding: token tctx does not match record tctx';
  if (claims.seq !== record.seq) return 'Binding: token seq does not match record seq';
  if (claims.sig_ref == null || typeof claims.sig_ref !== 'object' ||
      record.chain_ref == null || typeof record.chain_ref !== 'object') {
    return 'Binding: sig_ref or chain_ref missing or not an object';
  }
  if (claims.sig_ref.ledger_seq !== record.chain_ref.ledger_seq) {
    return 'Binding: sig_ref.ledger_seq does not match chain_ref.ledger_seq';
  }
  if ('segment_id' in claims.sig_ref && 'segment_id' in record.chain_ref) {
    if (claims.sig_ref.segment_id !== record.chain_ref.segment_id) {
      return 'Binding: sig_ref.segment_id does not match chain_ref.segment_id';
    }
  }
  return null;
}

// Convert raw 64-byte R||S signature to DER for Node.js crypto
function rawSigToDer(rawSig) {
  const r = rawSig.slice(0, 32);
  const s = rawSig.slice(32, 64);
  function toDerInt(buf) {
    let b = buf;
    // Strip leading zeros but keep at least one byte
    while (b.length > 1 && b[0] === 0) b = b.slice(1);
    // Prepend 0x00 if high bit set (avoid negative interpretation)
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
    return b;
  }
  const dr = toDerInt(r);
  const ds = toDerInt(s);
  const seq = Buffer.concat([
    Buffer.from([0x02, dr.length]), dr,
    Buffer.from([0x02, ds.length]), ds,
  ]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

// ── Key store ─────────────────────────────────────────────────────────────────

class KeyStore {
  constructor() { this._store = new Map(); }

  register(kid, publicKey) { this._store.set(kid, publicKey); }

  loadPem(kid, pemPath) {
    const pem = fs.readFileSync(pemPath, 'utf8');
    const key = crypto.createPublicKey(pem);
    this._store.set(kid, key);
  }

  lookup(kid) { return this._store.get(kid) || null; }

  /** Override in production to query your onboarding service. */
  refetch(kid) { return null; }
}

// ── Trust evaluation ──────────────────────────────────────────────────────────

function evaluateTrust(ledgerRecord) {
  const att = ledgerRecord.attestation_ref;
  if (!att) return TrustLevel.SOFTWARE_LAYER;
  switch (att.device_state) {
    case 'verified':         return TrustLevel.HARDWARE_BACKED;
    case 'hardware_keystore': return TrustLevel.HARDWARE_BOUND;
    case 'unknown':          return TrustLevel.EXECUTION_PROOF;
    case 'failed':           return TrustLevel.COMPROMISED_DEVICE;
    default:                 return TrustLevel.SOFTWARE_LAYER;
  }
}

// ── Evidence Token Verifier ───────────────────────────────────────────────────

class EvidenceTokenVerifier {
  /**
   * @param {KeyStore} keyStore
   * @param {object} opts
   * @param {number} opts.freshnessWindowMs  - default 300_000 (5 min)
   * @param {Map}    opts.dedupStore         - optional external dedup store
   * @param {Map}    opts.flowStore          - optional external flow store
   */
  constructor(keyStore, opts = {}) {
    this.keyStore          = keyStore;
    this.freshnessWindowMs = opts.freshnessWindowMs ?? DEFAULT_FRESHNESS_WINDOW_MS;
    this.dedupStore        = opts.dedupStore ?? new Map();
    this.flowStore         = opts.flowStore  ?? new Map();
  }

  verify(token, { skipFreshness = false } = {}) {
    const warnings = [];

    // ── Step 1: Parse JWS ───────────────────────────────────────────────────
    let headerB64, payloadB64, sigB64, jwsHeader, jwsPayloadBytes;
    token = token.trim();
    if (Buffer.byteLength(token, 'utf8') > MAX_JWS_COMPACT_UTF8_BYTES) {
      return reject(`Step 1: JWS compact token exceeds maximum size (${MAX_JWS_COMPACT_UTF8_BYTES} UTF-8 bytes)`);
    }
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return reject('Step 1: expected 3 dot-separated JWS segments');
      [headerB64, payloadB64, sigB64] = parts;
      const headerRaw = b64urlDecode(headerB64);
      if (headerRaw.length > MAX_JWS_HEADER_DECODED_BYTES) {
        return reject(`Step 1: JWS header exceeds maximum decoded size (${MAX_JWS_HEADER_DECODED_BYTES} bytes)`);
      }
      jwsPayloadBytes = b64urlDecode(payloadB64);
      if (jwsPayloadBytes.length > MAX_JWS_PAYLOAD_DECODED_BYTES) {
        return reject(`Step 1: JWS payload exceeds maximum decoded size (${MAX_JWS_PAYLOAD_DECODED_BYTES} bytes)`);
      }
      jwsHeader = JSON.parse(headerRaw.toString('utf8'));
    } catch (e) {
      return reject(`Step 1 (parse): ${e.message}`);
    }

    const hdrProd = validateJwsHeaderProduction(jwsHeader);
    if (hdrProd) return reject(hdrProd);

    if (!jwsHeader.alg) return reject("Step 1: missing 'alg' in JWS header");
    if (!jwsHeader.kid) return reject("Step 1: missing 'kid' in JWS header");

    const { alg, kid } = jwsHeader;
    if (!VALID_ALGORITHMS.has(alg)) {
      return reject(`Step 1: unsupported algorithm '${alg}'. Accepted: ${[...VALID_ALGORITHMS].join(', ')}`);
    }

    // ── Step 2: Resolve signing key ─────────────────────────────────────────
    let publicKey = this.keyStore.lookup(kid);
    if (!publicKey) {
      publicKey = this.keyStore.refetch(kid);
      if (!publicKey) return reject(`Step 2: unknown kid '${kid}'`);
      this.keyStore.register(kid, publicKey);
    }

    // ── Step 3: Verify signature ────────────────────────────────────────────
    try {
      const signingInput = Buffer.from(`${headerB64}.${payloadB64}`);
      const rawSig = b64urlDecode(sigB64);
      if (rawSig.length !== 64) {
        return reject(`Step 3: invalid ES256 signature length (${rawSig.length} bytes, expected 64)`);
      }
      const derSig  = rawSigToDer(rawSig);
      const verify  = crypto.createVerify('SHA256');
      verify.update(signingInput);
      if (!verify.verify(publicKey, derSig)) {
        return reject('Step 3: invalid signature');
      }
    } catch (e) {
      if (e.message.includes('ERR_OSSL') || e.message.includes('verify')) {
        return reject('Step 3: invalid signature');
      }
      return reject(`Step 3 (signature): ${e.message}`);
    }

    // ── Step 4: Parse and validate claims ───────────────────────────────────
    let claims;
    try { claims = JSON.parse(jwsPayloadBytes.toString('utf8')); }
    catch (e) { return reject(`Step 4 (parse claims): ${e.message}`); }

    const missing = [...REQUIRED_MINIMAL_FIELDS].filter(f => !(f in claims));
    if (missing.length) return reject(`Step 4: missing required fields: [${missing.sort().join(', ')}]`);

    // Normalise event field: spec uses 'event_name'; legacy tokens use 'event'.
    if (!('event_name' in claims)) {
      if ('event' in claims) {
        claims = Object.assign({}, claims, { event_name: claims.event });
        warnings.push("Step 4: legacy 'event' field found; use 'event_name' in new implementations.");
      } else {
        return reject("Step 4: missing required field 'event_name' (or legacy 'event')");
      }
    }

    // Q1: kid in JWS header and payload must be identical — both are signed material,
    // so a mismatch is structurally impossible in a legitimate token.
    if (claims.kid !== kid) {
      return reject(`Step 4: kid mismatch — header kid='${kid}' != payload kid='${claims.kid}'`);
    }

    // Q6: tctx must be a non-empty printable string with no whitespace.
    if (typeof claims.tctx !== 'string' || !claims.tctx || /\s/.test(claims.tctx) || !/^[\x21-\x7E\xA0-\uFFFF]+$/.test(claims.tctx)) {
      return reject("Step 4: 'tctx' must be a non-empty printable string with no whitespace");
    }

    if (!isValidUuid(claims.eid))   return reject("Step 4: 'eid' is not a valid UUID");
    if (!Number.isInteger(claims.seq)) return reject("Step 4: 'seq' must be an integer");
    if (!Number.isInteger(claims.ts))  return reject("Step 4: 'ts' must be an integer");
    if (typeof claims.sig_ref !== 'object' || !('ledger_seq' in claims.sig_ref)) {
      return reject("Step 4: 'sig_ref' must be an object with 'ledger_seq'");
    }
    // segment_id is required for new tokens; v1.0 signed tokens predate this requirement.
    // Warn but do not reject to maintain backward compatibility.
    if (!('segment_id' in claims.sig_ref)) {
      warnings.push(
        'Step 4: sig_ref.segment_id is absent. ' +
        'New token implementations MUST include segment_id. ' +
        'This token predates SPEC v1.1 and is accepted for backward compatibility.'
      );
    }
    if ('schema_v' in claims && claims.schema_v !== SUPPORTED_SCHEMA_VERSION) {
      warnings.push(
        `Step 4: schema_v=${claims.schema_v} > supported=${SUPPORTED_SCHEMA_VERSION}. Processing known fields only.`
      );
    }
    if ('boot_id' in claims && !isValidUuid(claims.boot_id)) {
      return reject("Step 4: 'boot_id' is not a valid UUID");
    }

    const sProd = validateTokenStringsProduction(claims);
    if (sProd) return reject(sProd);
    const iProd = validateTokenIntegersProduction(claims);
    if (iProd) return reject(iProd);

    // ── Step 5: Freshness ───────────────────────────────────────────────────
    if (!skipFreshness) {
      const ageMs = Math.abs(Date.now() - claims.ts);
      if (ageMs > this.freshnessWindowMs) {
        return reject(
          `Step 5: token outside freshness window (age=${ageMs}ms, window=${this.freshnessWindowMs}ms)`
        );
      }
    }

    // ── Step 6: Deduplicate ─────────────────────────────────────────────────
    // Use NUL byte (\x00) as separator — tctx is printable and can contain ':', so a colon
    // separator creates a collision class. NUL cannot appear in any valid printable field.
    const dedupKey = `${claims.did}\x00${claims.tctx}\x00${claims.event_name}\x00${claims.seq}`;
    // Store expiry_ms; prune expired entries to bound memory growth.
    // Expiry is insertion-based (SPEC: "MAY be pruned after 2 × freshnessWindowMs since insertion")
    // so static test fixtures with historical ts values don't expire immediately.
    const nowMsDedup = Date.now();
    const dedupExpiryMs = nowMsDedup + 2 * this.freshnessWindowMs;
    for (const [k, exp] of this.dedupStore) {
      if (exp <= nowMsDedup) this.dedupStore.delete(k);
    }
    if (this.dedupStore.has(dedupKey)) {
      return reject(
        `Step 6: duplicate token (did=${claims.did}, tctx=${claims.tctx}, event_name=${claims.event_name}, seq=${claims.seq})`
      );
    }
    this.dedupStore.set(dedupKey, dedupExpiryMs);

    // ── Step 7: Retry correlation ───────────────────────────────────────────
    const retryEvents = new Set(['payment.retry', 'pos.txn.retry', 'login.retry', 'auth.retry']);
    if (retryEvents.has(claims.event_name)) {
      const prior = this.flowStore.get(claims.tctx) || [];
      if (prior.length) {
        const maxPriorSeq = Math.max(...prior.map(a => a.seq));
        if (claims.seq <= maxPriorSeq) {
          return reject(
            `Step 7: sequence regression in retry. seq=${claims.seq} <= prior max=${maxPriorSeq}`
          );
        }
        const priorBoot   = prior[0].boot_id;
        const currentBoot = claims.boot_id;
        if (priorBoot && currentBoot && priorBoot !== currentBoot) {
          warnings.push(
            `Step 7: boot_id changed mid-flow. May indicate device reboot between retries — review policy.`
          );
        }
      }
    }
    const flow = this.flowStore.get(claims.tctx) || [];
    flow.push(claims);
    this.flowStore.set(claims.tctx, flow);

    // ── Step 8: Trust level ─────────────────────────────────────────────────
    warnings.push(
      'Step 8: ledger record not fetched. Trust level is software_layer. ' +
      'Fetch the full Evidence Record via sig_ref.ledger_seq for dispute-grade trust.'
    );

    return valid(claims, TrustLevel.SOFTWARE_LAYER, warnings);
  }
}

// ── Canonical JSON (deep key sort, matches Python json.dumps sort_keys=True) ──

function _deepSortKeys(obj) {
  if (Array.isArray(obj)) return obj.map(_deepSortKeys);
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.keys(obj).sort().map(k => [k, _deepSortKeys(obj[k])])
    );
  }
  return obj;
}

// ── Evidence Record Verifier ──────────────────────────────────────────────────

class EvidenceRecordVerifier {
  constructor(keyStore) { this.keyStore = keyStore; }

  verify(record) {
    const warnings = [];

    // ts_source: MUST be present; unknown values are warnings not rejections.
    const tsSource = record.ts_source;
    if (tsSource === undefined || tsSource === null) {
      return reject("Record missing required 'ts_source' field");
    }
    if (!VALID_TS_SOURCES.has(tsSource)) {
      warnings.push(
        `Record ts_source='${tsSource}' is not a recognised value ` +
        `(${[...VALID_TS_SOURCES].sort().join(', ')}). Treat timestamp with caution.`
      );
    }

    // M6: validate measured_at on all signals — must not exceed record ts + tolerance
    const recordTs = record.ts;
    if (recordTs != null) {
      for (const sigEntry of (record.signals || [])) {
        if (sigEntry.measured_at != null && sigEntry.measured_at > recordTs + SIGNAL_CLOCK_SKEW_TOLERANCE_MS) {
          return reject(
            `Record signal '${sigEntry.signal || '?'}' has measured_at=${sigEntry.measured_at} ` +
            `which exceeds record ts=${recordTs} + tolerance=${SIGNAL_CLOCK_SKEW_TOLERANCE_MS}ms. ` +
            'A signal cannot be measured after the event it is reported with.'
          );
        }
      }
    }

    const sigObj = record.sig;
    if (!sigObj)        return reject("Record missing 'sig' field");

    // S1: reject non-ES256 algo before attempting signature verification
    if (sigObj.algo !== 'ES256') {
      return reject(`Record sig.algo must be 'ES256'; got '${sigObj.algo}'`);
    }

    if (!sigObj.key_id) return reject("Record sig missing 'key_id'");
    if (!sigObj.value) return reject("Record sig missing 'value'");

    let publicKey = this.keyStore.lookup(sigObj.key_id);
    if (!publicKey) {
      publicKey = this.keyStore.refetch(sigObj.key_id);
      if (!publicKey) return reject(`Unknown key_id '${sigObj.key_id}'`);
      this.keyStore.register(sigObj.key_id, publicKey);
    }

    const { sig: _sig, ...recordNoSig } = record;
    // Canonical form: deep-sorted keys, no spaces — must match the signing device
    const canonical = Buffer.from(JSON.stringify(_deepSortKeys(recordNoSig)));

    try {
      const rawSig = b64urlDecode(sigObj.value);
      const derSig = rawSigToDer(rawSig);
      const v = crypto.createVerify('SHA256');
      v.update(canonical);
      if (!v.verify(publicKey, derSig)) return reject('Record signature invalid');
    } catch (e) {
      return reject(`Record signature error: ${e.message}`);
    }

    return valid(null, evaluateTrust(record), warnings);
  }

  /**
   * Verify hash-chain integrity across a sequence of Evidence Records.
   *
   * NOTE: Checks chain integrity only (hash linkage and event_hash recomputation).
   * Does NOT verify device signatures on individual records. For full validation
   * callers MUST also call verify(record) on each record in the chain.
   */
  verifyChain(records) {
    if (!records || records.length === 0) {
      return valid(null, null);
    }
    const ZEROS64 = '0'.repeat(64);
    const sorted = [...records].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    let prevHash = null;
    let prevSegmentId = null;

    for (const record of sorted) {
      const chainRef  = record.chain_ref ?? {};
      if (chainRef.hash_algo !== 'sha-256') {
        return reject(`chain_ref.hash_algo must be 'sha-256'; got '${chainRef.hash_algo}' at seq=${record.seq}`);
      }
      const storedHash = chainRef.event_hash;
      const storedPrev = chainRef.prev_hash;

      const normEvent = normalizeHex64(storedHash);
      if (!normEvent) {
        return reject(`chain_ref.event_hash must be 64 hexadecimal digits at seq=${record.seq}`);
      }
      const normPrevStored = storedPrev != null ? normalizeHex64(storedPrev) : null;
      if (storedPrev != null && !normPrevStored) {
        return reject(`chain_ref.prev_hash must be 64 hexadecimal digits at seq=${record.seq}`);
      }

      // S2: First record of each segment MUST carry all-zero prev_hash (SPEC.md §chain_ref).
      // Detected when seq===0 (globally first record) or segment_id increments between records.
      const curSegmentId = chainRef.segment_id != null ? Number(chainRef.segment_id) : null;
      const isSegmentStart = record.seq === 0 ||
        (curSegmentId !== null && prevSegmentId !== null && curSegmentId !== prevSegmentId);
      if (isSegmentStart && normPrevStored && normPrevStored !== ZEROS64) {
        return reject(
          `Chain break at seq=${record.seq}: first record of segment must have all-zero prev_hash`
        );
      }

      // Compute expected event_hash
      const { sig: _sig, ...recordNoSig } = record;
      const forHash = JSON.parse(JSON.stringify(recordNoSig));
      forHash.chain_ref.event_hash = '0'.repeat(64);
      const canonical = Buffer.from(JSON.stringify(_deepSortKeys(forHash)));
      const computedHash  = crypto.createHash('sha256').update(canonical).digest('hex');

      if (computedHash !== normEvent) {
        return reject(
          `Chain break at seq=${record.seq}: event_hash mismatch ` +
          `(stored=${storedHash?.slice(0,16)}..., computed=${computedHash.slice(0,16)}...)`
        );
      }
      if (prevHash !== null) {
        if (!normPrevStored) {
          return reject(`Chain break at seq=${record.seq}: chain_ref.prev_hash missing or not 64 hex digits`);
        }
        if (normPrevStored !== prevHash) {
          return reject(
            `Chain break at seq=${record.seq}: prev_hash mismatch ` +
            `(stored=${storedPrev?.slice(0,16)}..., expected=${prevHash.slice(0,16)}...)`
          );
        }
      }
      prevHash = normEvent;
      prevSegmentId = curSegmentId;
    }
    return valid(null, null);
  }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

if (require.main === module) {
  const args = process.argv.slice(2);
  const get  = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : null; };
  const has  = (flag) => args.includes(flag);

  const pubkeyPath    = get('--pubkey');
  const tokenStr      = get('--token');
  const tokenFile     = get('--token-file');
  const recordFile    = get('--record');
  const skipFreshness = has('--skip-freshness');

  if (!pubkeyPath) {
    console.error('Usage: node verifier.js --pubkey <pem_path> [--token <jws>|--token-file <path>|--record <path>] [--skip-freshness]');
    process.exit(1);
  }

  const DEMO_KID = 'yinkoshield.device.sign.v1';
  const store = new KeyStore();
  store.loadPem(DEMO_KID, pubkeyPath);

  if (recordFile) {
    const record = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
    const rv     = new EvidenceRecordVerifier(store);
    const result = rv.verify(record);
    console.log(`\nEvidence Record: ${result.status.toUpperCase()}`);
    if (result.reason)     console.log(`  Reason:      ${result.reason}`);
    if (result.trustLevel) console.log(`  Trust level: ${result.trustLevel}`);
    process.exit(result.ok ? 0 : 1);
  }

  const token = tokenStr ?? (tokenFile ? fs.readFileSync(tokenFile, 'utf8').trim() : null);
  if (!token) {
    console.error('Provide --token, --token-file, or --record');
    process.exit(1);
  }

  const verifier = new EvidenceTokenVerifier(store);
  const result   = verifier.verify(token, { skipFreshness });

  console.log(`\nToken: ${result.status.toUpperCase()}`);
  if (result.reason) console.log(`  Reason:  ${result.reason}`);
  if (result.claims) {
    console.log(`  Event:   ${result.claims.event_name}`);
    console.log(`  Device:  ${result.claims.did}`);
    console.log(`  seq:     ${result.claims.seq}`);
    console.log(`  tctx:    ${result.claims.tctx}`);
  }
  if (result.trustLevel) console.log(`  Trust:   ${result.trustLevel}`);
  result.warnings.forEach(w => console.log(`  ⚠  ${w}`));
  process.exit(result.ok ? 0 : 1);
}

module.exports = {
  EvidenceTokenVerifier,
  EvidenceRecordVerifier,
  KeyStore,
  TrustLevel,
  VerificationStatus,
  VerificationResult,
  evaluateTrust,
  verifyTokenRecordBinding,
  normalizeHex64,
  _deepSortKeys,
  b64urlDecode,
  isValidUuid,
  rawSigToDer,
};
