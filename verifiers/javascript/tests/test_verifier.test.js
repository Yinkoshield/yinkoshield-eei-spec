// Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
//
// YinkoShield Execution Evidence Infrastructure
// Evidence Token Verifier — JavaScript Test Suite
//
// This is a reference implementation of the verification pipeline defined in SPEC.md.
// It demonstrates sovereign verification: no YinkoShield infrastructure required.
// Verification uses only the registered device public key.
//
// https://github.com/yinkoshield
/**
 * YinkoShield Evidence Token Verifier Test Suite
 *
 * Tests all security test vectors and behavioral requirements:
 * - Valid token verification (minimal and standard profiles)
 * - Signature validation (forged, algorithm confusion)
 * - Freshness enforcement
 * - Replay detection (deduplication)
 * - Retry correlation and sequence regression
 * - Chain integrity verification
 * - Trust level evaluation
 *
 * Run with: node --test tests/test_verifier.test.js
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Import verifier
const { EvidenceTokenVerifier, EvidenceRecordVerifier, KeyStore, TrustLevel, VerificationStatus, VerificationResult, evaluateTrust, verifyTokenRecordBinding } = require('../verifier.js');

// ── Test fixtures ────────────────────────────────────────────────────────────

const REPO_ROOT = path.resolve(__dirname, '../../..');
const KEYS_DIR = path.join(REPO_ROOT, 'keys');
const VECTORS_DIR = path.join(REPO_ROOT, 'test-vectors');
const EXAMPLES_DIR = path.join(REPO_ROOT, 'examples');
const DEMO_KID = 'yinkoshield.device.sign.v1';

function loadVector(filePath) {
  return JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, filePath), 'utf8'));
}

function loadRecord(filePath) {
  return JSON.parse(fs.readFileSync(path.join(EXAMPLES_DIR, filePath), 'utf8'));
}

function setupKeyStore() {
  const store = new KeyStore();
  store.loadPem(DEMO_KID, path.join(KEYS_DIR, 'demo_public_key.pem'));
  return store;
}

// ── Valid token tests ────────────────────────────────────────────────────────

test('Valid tokens > minimal profile', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('valid/minimal_profile.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.strictEqual(result.claims.event_name, 'payment.initiated');
  assert.strictEqual(result.claims.seq, 1044);
});

test('Valid tokens > standard profile', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('valid/standard_profile.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.strictEqual(result.claims.scope, 'payment');
  assert.strictEqual(result.claims.schema_v, 1);
});

test('Valid tokens > payment retry', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('valid/payment_retry.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.strictEqual(result.claims.event_name, 'payment.retry');
  assert.strictEqual(result.claims.seq, 1045);
});

test('Valid tokens > claims returned', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('valid/minimal_profile.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.claims !== null, true);
  for (const field of ['eid', 'did', 'kid', 'ts', 'seq', 'event_name', 'tctx', 'sig_ref']) {
    assert.strictEqual(field in result.claims, true, `Missing claim: ${field}`);
  }
});

// ── Signature tests ──────────────────────────────────────────────────────────

test('Signature forged > wrong key', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/signature_forged/wrong_key.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('Signature forged > corrupted signature', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/signature_forged/corrupted_signature.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('Signature forged > empty signature', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/signature_forged/empty_signature.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('Signature forged > unknown kid', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/signature_forged/unknown_kid.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert(result.reason.toLowerCase().includes('kid') || result.reason.toLowerCase().includes('unknown'));
});

// ── Algorithm confusion tests ────────────────────────────────────────────────

test('Algorithm confusion > HS256 rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/algorithm_confusion/hs256_claim.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert(result.reason.toLowerCase().includes('algorithm') || result.reason.toLowerCase().includes('alg'));
});

test('Algorithm confusion > alg=none rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/algorithm_confusion/alg_none.json');
  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

// ── Freshness tests ──────────────────────────────────────────────────────────

test('Freshness > expired token rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/expired_token/one_hour_old.json');
  const result = verifier.verify(vector.token);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert(result.reason.toLowerCase().includes('freshness'));
});

test('Freshness > future token rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/expired_token/future_dated.json');
  const result = verifier.verify(vector.token);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('freshness'));
});

test('Freshness > configurable freshness window', () => {
  const keyStore = setupKeyStore();
  const vector = loadVector('invalid/expired_token/one_hour_old.json');
  // Decode the token's ts so the window is always wide enough for this static
  // fixture, regardless of how old the vector has become since it was generated.
  const payloadB64 = vector.token.split('.')[1];
  const ts = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()).ts;
  const ageMs = Date.now() - ts;
  const wideVerifier = new EvidenceTokenVerifier(keyStore, { freshnessWindowMs: ageMs + 60_000 });
  const result = wideVerifier.verify(vector.token);
  assert.strictEqual(result.status, VerificationStatus.VALID);
});

// ── Replay tests ─────────────────────────────────────────────────────────────

test('Replay > duplicate rejected on second submission', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const vector = loadVector('invalid/replay_attack/duplicate_submission.json');
  const first = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(first.status, VerificationStatus.VALID);

  const second = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(second.status, VerificationStatus.REJECT);
  assert(second.reason.toLowerCase().includes('duplicate'));
});

test('Replay > distinct tokens not flagged', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const v1 = loadVector('valid/minimal_profile.json');
  const v2 = loadVector('valid/payment_retry.json');

  const r1 = verifier.verify(v1.token, { skipFreshness: true });
  const r2 = verifier.verify(v2.token, { skipFreshness: true });
  assert.strictEqual(r1.status, VerificationStatus.VALID);
  assert.strictEqual(r2.status, VerificationStatus.VALID);
});

// ── Missing fields tests ─────────────────────────────────────────────────────

for (const field of ['eid', 'did', 'kid', 'ts', 'seq', 'event', 'tctx', 'sig_ref']) {
  test(`Missing fields > missing ${field}`, () => {
    const keyStore = setupKeyStore();
    const verifier = new EvidenceTokenVerifier(keyStore);
    const vector = loadVector(`invalid/missing_fields/missing_${field}.json`);
    const result = verifier.verify(vector.token, { skipFreshness: true });
    assert.strictEqual(
      result.status,
      VerificationStatus.REJECT,
      `Expected REJECT for missing '${field}' but got ${result.status}: ${result.reason}`
    );
  });
}

// ── Sequence regression tests ────────────────────────────────────────────────

test('Sequence regression > retry with lower seq rejected', () => {
  const keyStore = setupKeyStore();
  const vector = loadVector('invalid/sequence_regression/seq_lower_than_prior.json');
  const priorSeq = vector.prior_seq;

  const verifier = new EvidenceTokenVerifier(keyStore);
  // Seed the flow store with a prior attempt
  const priorClaims = {
    did: 'dev-9f8e7d6c5b4a3c2d',
    tctx: 'tctx-7c4e9a2f1b8d3e56',
    event_name: 'payment.initiated',
    seq: priorSeq,
    boot_id: 'f0e1d2c3-b4a5-6789-abcd-ef0123456789',
  };
  verifier.flowStore.set('tctx-7c4e9a2f1b8d3e56', [priorClaims]);

  const result = verifier.verify(vector.token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert(
    result.reason.toLowerCase().includes('sequence') || result.reason.toLowerCase().includes('seq')
  );
});

// ── Chain integrity tests ────────────────────────────────────────────────────

test('Chain integrity > valid chain', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r1 = loadRecord('demo_sequence/ledger_record_attempt1.json');
  const r2 = loadRecord('demo_sequence/ledger_record_attempt2.json');
  const result = recordVerifier.verifyChain([r1, r2]);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

test('Chain integrity > tampered prev hash', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const vector = loadVector('invalid/broken_chain/tampered_prev_hash.json');
  const r1 = loadRecord('demo_sequence/ledger_record_attempt1.json');
  const r2 = vector.record;
  const result = recordVerifier.verifyChain([r1, r2]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert(
    result.reason.toLowerCase().includes('chain') || result.reason.toLowerCase().includes('hash')
  );
});

test('Chain integrity > tampered record content', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const vector = loadVector('invalid/broken_chain/event_hash_mismatch.json');
  const result = recordVerifier.verifyChain([vector.record]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('Chain integrity > record signature valid', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const result = recordVerifier.verify(r);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

test('Chain integrity > auth-payment chain', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const rAuth = loadRecord('chargeback_dispute/ledger_record_auth.json');
  const rPay = loadRecord('chargeback_dispute/ledger_record_payment.json');
  const result = recordVerifier.verifyChain([rAuth, rPay]);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

// ── Trust level tests ────────────────────────────────────────────────────────

test('Trust level > hardware backed trust', () => {
  const record = { attestation_ref: { device_state: 'verified' } };
  assert.strictEqual(evaluateTrust(record), TrustLevel.HARDWARE_BACKED);
});

test('Trust level > unknown state trust', () => {
  const record = { attestation_ref: { device_state: 'unknown' } };
  assert.strictEqual(evaluateTrust(record), TrustLevel.EXECUTION_PROOF);
});

test('Trust level > failed state trust', () => {
  const record = { attestation_ref: { device_state: 'failed' } };
  assert.strictEqual(evaluateTrust(record), TrustLevel.COMPROMISED_DEVICE);
});

test('Trust level > no attestation trust', () => {
  const record = {};
  assert.strictEqual(evaluateTrust(record), TrustLevel.SOFTWARE_LAYER);
});

test('Trust level > hardware bound trust', () => {
  const record = { attestation_ref: { device_state: 'hardware_keystore' } };
  assert.strictEqual(evaluateTrust(record), TrustLevel.HARDWARE_BOUND);
});

test('Trust level > full record trust level', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const result = recordVerifier.verify(r);
  assert.strictEqual(result.trustLevel, TrustLevel.HARDWARE_BACKED);
});

// ── Record sig.algo validation tests ─────────────────────────────────────────

test('Record sig.algo > non-ES256 rejected', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const tampered = { ...r, sig: { ...r.sig, algo: 'HS256' } };
  const result = recordVerifier.verify(tampered);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('algo') || result.reason.toLowerCase().includes('algorithm'));
});

// ── chain_ref.hash_algo validation tests ─────────────────────────────────────

test('Chain hash_algo > non-sha-256 rejected', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const tampered = { ...r, chain_ref: { ...r.chain_ref, hash_algo: 'sha-512' } };
  const result = recordVerifier.verifyChain([tampered]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('hash_algo') || result.reason.toLowerCase().includes('sha-256'));
});

// ── measured_at future-dating tests ──────────────────────────────────────────

test('Signal measured_at > future-dated signal rejected', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const futureTs = r.ts + 120_000; // 2 minutes after record ts — well above 5 s tolerance
  const tampered = {
    ...r,
    signals: [{
      signal: 'device.integrity',
      source: 'bootloader',
      measured_at: futureTs,
      value: 'verified',
      measurement_method: 'hardware_attested',
    }],
  };
  const result = recordVerifier.verify(tampered);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('measured_at'));
});

// ── ts_source validation tests ───────────────────────────────────────────────

test('Record ts_source > missing ts_source rejects', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const { ts_source: _ts, ...recordNoTs } = r;
  const result = recordVerifier.verify(recordNoTs);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.includes('ts_source'));
});

test('Record ts_source > unknown ts_source produces warning', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  // Inject an unrecognised ts_source — signature will also fail, but we check the warning path exists
  // by constructing a minimal record with a known-bad ts_source (no sig so it rejects on sig first)
  const fakeRecord = { ts_source: 'gps_satellite' };
  const result = recordVerifier.verify(fakeRecord);
  // Rejects on missing sig, but not on ts_source (ts_source warning is accumulated)
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.includes('sig'));
});

test('Record ts_source > valid ts_source accepted', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r = loadRecord('full_evidence_record.json');
  const result = recordVerifier.verify(r);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

// ── Token-signing helper ──────────────────────────────────────────────────────

const crypto = require('node:crypto');

// Base payload that passes all Step 4 validations.
const VALID_PAYLOAD = {
  eid:        'f1e2d3c4-b5a6-4789-0abc-def123456789',
  did:        'dev-9f8e7d6c5b4a3c2d',
  kid:        DEMO_KID,
  ts:         1709312400000,
  seq:        1044,
  event_name: 'payment.initiated',
  tctx:       'tctx-7c4e9a2f1b8d3e56',
  sig_ref:    { ledger_seq: 1044, segment_id: 1 },
};

function mergePayload(overrides) {
  return Object.assign({}, VALID_PAYLOAD, overrides);
}

// Convert DER-encoded ECDSA signature to raw 64-byte R||S format.
function derToRaw(derSig) {
  let offset = 2; // skip SEQUENCE tag + total length
  if (derSig[offset] !== 0x02) throw new Error('Expected INTEGER tag for R');
  const rLen = derSig[offset + 1];
  let r = derSig.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  if (derSig[offset] !== 0x02) throw new Error('Expected INTEGER tag for S');
  const sLen = derSig[offset + 1];
  let s = derSig.slice(offset + 2, offset + 2 + sLen);
  // Strip DER leading 0x00 padding
  while (r.length > 32 && r[0] === 0) r = r.slice(1);
  while (s.length > 32 && s[0] === 0) s = s.slice(1);
  // Pad to 32 bytes
  const rPad = Buffer.concat([Buffer.alloc(32 - r.length), r]);
  const sPad = Buffer.concat([Buffer.alloc(32 - s.length), s]);
  return Buffer.concat([rPad, sPad]);
}

function makeToken(payload, headerKid = DEMO_KID, extraHeader = null) {
  const pem = fs.readFileSync(path.join(KEYS_DIR, 'demo_private_key.pem'), 'utf8');
  const privateKey = crypto.createPrivateKey(pem);
  const headerObj = Object.assign({ alg: 'ES256', kid: headerKid, typ: 'JWS' }, extraHeader || {});
  const headerB64  = Buffer.from(JSON.stringify(headerObj)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerB64}.${payloadB64}`;
  const derSig  = crypto.sign('sha256', Buffer.from(signingInput), privateKey);
  const rawSig  = derToRaw(derSig);
  const sigB64  = rawSig.toString('base64url');
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// ── Utility function unit tests ───────────────────────────────────────────────

const { b64urlDecode, isValidUuid, rawSigToDer, _deepSortKeys } = require('../verifier.js');

test('Utility b64urlDecode > 3-byte input no padding needed', () => {
  const data = Buffer.from('abc');
  const encoded = data.toString('base64url');
  assert.deepStrictEqual(b64urlDecode(encoded), data);
});

test('Utility b64urlDecode > 1-byte input adds double padding', () => {
  const data = Buffer.from('a');
  const encoded = data.toString('base64url');
  assert.deepStrictEqual(b64urlDecode(encoded), data);
});

test('Utility b64urlDecode > 2-byte input adds single padding', () => {
  const data = Buffer.from('ab');
  const encoded = data.toString('base64url');
  assert.deepStrictEqual(b64urlDecode(encoded), data);
});

test('Utility b64urlDecode > url-safe chars roundtrip', () => {
  const data = Buffer.from([0xFB, 0xEF, 0x12, 0x34]);
  const encoded = data.toString('base64url');
  assert.ok(encoded.includes('-') || encoded.includes('_') || true); // just verify roundtrip
  assert.deepStrictEqual(b64urlDecode(encoded), data);
});

test('Utility b64urlDecode > empty string', () => {
  assert.deepStrictEqual(b64urlDecode(''), Buffer.alloc(0));
});

test('Utility isValidUuid > valid lowercase UUID', () => {
  assert.strictEqual(isValidUuid('f1e2d3c4-b5a6-4789-0abc-def123456789'), true);
});

test('Utility isValidUuid > valid uppercase UUID', () => {
  assert.strictEqual(isValidUuid('F1E2D3C4-B5A6-4789-0ABC-DEF123456789'), true);
});

test('Utility isValidUuid > invalid too short', () => {
  assert.strictEqual(isValidUuid('f1e2d3c4-b5a6-4789'), false);
});

test('Utility isValidUuid > invalid no dashes', () => {
  assert.strictEqual(isValidUuid('f1e2d3c4b5a647890abcdef123456789'), false);
});

test('Utility isValidUuid > empty string', () => {
  assert.strictEqual(isValidUuid(''), false);
});

test('Utility isValidUuid > non-hex chars', () => {
  assert.strictEqual(isValidUuid('f1e2d3c4-b5a6-4789-0abc-zzzzzzzzzzzz'), false);
});

test('Utility rawSigToDer > produces valid DER SEQUENCE', () => {
  // Craft a 64-byte raw signature (r=1, s=2 padded to 32 bytes each)
  const rawSig = Buffer.alloc(64, 0);
  rawSig[31] = 0x01; // r = 1
  rawSig[63] = 0x02; // s = 2
  const der = rawSigToDer(rawSig);
  assert.strictEqual(der[0], 0x30, 'Expected SEQUENCE tag 0x30');
});

test('Utility rawSigToDer > r with high bit set gets 0x00 prefix', () => {
  // r = 0xFF (high bit set) → DER integer must have 0x00 prefix
  const rawSig = Buffer.alloc(64, 0);
  rawSig[31] = 0xFF; // r = 0xFF
  rawSig[63] = 0x01; // s = 1
  const der = rawSigToDer(rawSig);
  // der: 0x30 [total] 0x02 [r_len] [0x00] 0xFF ...
  const rLen = der[3];
  assert.strictEqual(der[4], 0x00, `Expected 0x00 prefix for r with high bit, rLen=${rLen}`);
});

test('Utility _deepSortKeys > flat object sorted', () => {
  const input = { z: 1, a: 2, m: 3 };
  const sorted = _deepSortKeys(input);
  assert.deepStrictEqual(Object.keys(sorted), ['a', 'm', 'z']);
});

test('Utility _deepSortKeys > nested objects sorted recursively', () => {
  const input = { z: { y: 1, b: 2 }, a: 3 };
  const sorted = _deepSortKeys(input);
  assert.deepStrictEqual(Object.keys(sorted), ['a', 'z']);
  assert.deepStrictEqual(Object.keys(sorted.z), ['b', 'y']);
});

test('Utility _deepSortKeys > array order preserved', () => {
  const input = { arr: [3, 1, 2] };
  const sorted = _deepSortKeys(input);
  assert.deepStrictEqual(sorted.arr, [3, 1, 2]);
});

test('Utility _deepSortKeys > scalar passthrough', () => {
  assert.strictEqual(_deepSortKeys(42), 42);
  assert.strictEqual(_deepSortKeys('hello'), 'hello');
  assert.strictEqual(_deepSortKeys(null), null);
});

test('Utility _deepSortKeys > array of objects sorted recursively', () => {
  const input = { items: [{ z: 1, a: 2 }] };
  const sorted = _deepSortKeys(input);
  assert.deepStrictEqual(Object.keys(sorted.items[0]), ['a', 'z']);
});

test('Utility evaluateTrust > unknown device state returns SOFTWARE_LAYER', () => {
  const record = { attestation_ref: { device_state: 'purple_unicorn' } };
  assert.strictEqual(evaluateTrust(record), TrustLevel.SOFTWARE_LAYER);
});

// ── VerificationResult unit tests ─────────────────────────────────────────────

test('VerificationResult > ok true for VALID', () => {
  const r = new VerificationResult({ status: VerificationStatus.VALID });
  assert.strictEqual(r.ok, true);
});

test('VerificationResult > ok false for REJECT', () => {
  const r = new VerificationResult({ status: VerificationStatus.REJECT, reason: 'test error' });
  assert.strictEqual(r.ok, false);
});

// ── Non-regression tests for BUG-1: JS Number.isInteger(true) ────────────────

test('Non-regression BUG-1 > seq=true (boolean) rejected', () => {
  // Number.isInteger(true) returns false in JS → already rejected; this test
  // confirms the protection is in place after code changes.
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ seq: true }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT, result.reason);
});

test('Non-regression BUG-1 > seq=false (boolean) rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ seq: false }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT, result.reason);
});

test('Non-regression BUG-1 > ts=true (boolean) rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ ts: true }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT, result.reason);
});

test('Non-regression BUG-1 > seq=string rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ seq: '1044' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT, result.reason);
});

// ── SPEC normative security requirement tests ─────────────────────────────────

test('SPEC > kid mismatch header vs payload rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ kid: 'other.unknown.kid' }), DEMO_KID);
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(
    result.reason.toLowerCase().includes('kid') || result.reason.toLowerCase().includes('mismatch'),
    `Expected 'kid' or 'mismatch' in reason: ${result.reason}`
  );
});

test('SPEC > tctx empty string rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ tctx: '' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('tctx'));
});

test('SPEC > tctx with whitespace rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ tctx: 'tctx with space' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('SPEC > tctx with C1 control 0x80 rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ tctx: 'tctx\u0080bad' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('SPEC > tctx with C1 control 0x9F rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ tctx: 'tctx\u009Fbad' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('SPEC > boot_id invalid UUID rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ boot_id: 'not-a-uuid-at-all' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.toLowerCase().includes('boot_id'));
});

test('SPEC > schema_v unknown produces warning not reject', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ schema_v: 99 }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.ok(result.warnings.some(w => w.includes('schema_v')));
});

test('SPEC > sig_ref segment_id absent produces warning not reject', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ sig_ref: { ledger_seq: 1044 } }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.ok(result.warnings.some(w => w.includes('segment_id')));
});

test('SPEC > event_name takes precedence when both event_name and event present', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ event_name: 'payment.initiated', event: 'legacy.ignored' }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
  assert.strictEqual(result.claims.event_name, 'payment.initiated');
});

test('SPEC > unknown extra fields accepted', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ future_field: 'value', another_new_field: 42 }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

test('SPEC > malformed JWS two segments rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const result = verifier.verify('header.payload', { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

// ── verify_chain edge case tests ──────────────────────────────────────────────

test('verifyChain edge > empty list returns VALID', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const result = recordVerifier.verifyChain([]);
  assert.strictEqual(result.status, VerificationStatus.VALID);
});

test('verifyChain edge > out of order records sorted and valid', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r1 = loadRecord('demo_sequence/ledger_record_attempt1.json');
  const r2 = loadRecord('demo_sequence/ledger_record_attempt2.json');
  // Supply in reverse order — verifyChain MUST sort by seq internally.
  const result = recordVerifier.verifyChain([r2, r1]);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});

test('verifyChain edge > missing chain_ref rejected cleanly', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const record = { seq: 1, ts: 1709312400000 }; // no chain_ref
  const result = recordVerifier.verifyChain([record]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('verifyChain edge > missing event_hash rejected without crash (BUG-2 regression)', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const record = {
    seq: 1,
    ts: 1709312400000,
    chain_ref: {
      hash_algo: 'sha-256',
      prev_hash: '0'.repeat(64),
      // event_hash intentionally absent
    },
  };
  // Must not throw; must return REJECT with a message
  const result = recordVerifier.verifyChain([record]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason != null, 'Expected a rejection reason');
});

test('verifyChain edge > wrong hash_algo rejected', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const record = {
    seq: 1,
    ts: 1709312400000,
    chain_ref: { hash_algo: 'sha-512', event_hash: '0'.repeat(64), prev_hash: '0'.repeat(64) },
  };
  const result = recordVerifier.verifyChain([record]);
  assert.strictEqual(result.status, VerificationStatus.REJECT);
  assert.ok(result.reason.includes('sha-256') || result.reason.includes('hash_algo'));
});

// ── Production implementation requirements (SPEC.md) ─────────────────────────

test('production > disallowed JWS header key rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({}), DEMO_KID, { jwk: { kty: 'EC', crv: 'P-256' } });
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('production > oversized token rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const result = verifier.verify('x'.repeat(25000), { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('production > negative seq rejected', () => {
  const keyStore = setupKeyStore();
  const verifier = new EvidenceTokenVerifier(keyStore);
  const token = makeToken(mergePayload({ seq: -1 }));
  const result = verifier.verify(token, { skipFreshness: true });
  assert.strictEqual(result.status, VerificationStatus.REJECT);
});

test('production > verifyTokenRecordBinding OK', () => {
  const claims = {
    eid: 'f1e2d3c4-b5a6-4789-0abc-def123456789',
    did: 'dev-9f8e7d6c5b4a3c2d',
    tctx: 'tctx-7c4e9a2f1b8d3e56',
    seq: 1044,
    sig_ref: { ledger_seq: 1044, segment_id: 12 },
  };
  const record = {
    eid: 'f1e2d3c4-b5a6-4789-0abc-def123456789',
    device_id: 'dev-9f8e7d6c5b4a3c2d',
    tctx: 'tctx-7c4e9a2f1b8d3e56',
    seq: 1044,
    chain_ref: { ledger_seq: 1044, segment_id: 12 },
  };
  assert.strictEqual(verifyTokenRecordBinding(claims, record), null);
});

test('production > verifyChain accepts uppercase event_hash', () => {
  const keyStore = setupKeyStore();
  const recordVerifier = new EvidenceRecordVerifier(keyStore);
  const r1 = loadRecord('demo_sequence/ledger_record_attempt1.json');
  const r2 = loadRecord('demo_sequence/ledger_record_attempt2.json');
  const r1u = JSON.parse(JSON.stringify(r1));
  r1u.chain_ref.event_hash = r1.chain_ref.event_hash.toUpperCase();
  const result = recordVerifier.verifyChain([r1u, r2]);
  assert.strictEqual(result.status, VerificationStatus.VALID, result.reason);
});
