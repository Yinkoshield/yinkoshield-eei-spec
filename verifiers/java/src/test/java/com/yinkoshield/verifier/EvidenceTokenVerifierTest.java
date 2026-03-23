/*
 * Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
 * SPDX-License-Identifier: Apache-2.0
 *
 * YinkoShield Execution Evidence Infrastructure
 * Evidence Token Verifier — Java Test Suite
 *
 * https://github.com/yinkoshield
 */
package com.yinkoshield.verifier;

import com.yinkoshield.verifier.EvidenceTokenVerifier.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the 8-step verification pipeline against all security test vectors
 * and behavioral scenarios including replay detection, retry correlation,
 * trust level evaluation, and SPEC normative requirements.
 *
 * <p>Test vectors are read from {@code test-vectors/} relative to the repo root.
 * Demo key material is read from {@code keys/}.
 * Crafted tokens (BUG-1 non-regression, kid mismatch, etc.) are signed on the fly
 * using {@code keys/demo_private_key.pem} via the {@code makeToken} helper.
 */
class EvidenceTokenVerifierTest {

    private static final String DEMO_KID = "yinkoshield.device.sign.v1";
    private static final Path REPO_ROOT = findRepoRoot();
    private static final Path VECTORS = REPO_ROOT.resolve("test-vectors");
    private static final Path EXAMPLES = REPO_ROOT.resolve("examples");
    private static final Path KEYS = REPO_ROOT.resolve("keys");

    private KeyStore keyStore;
    private EvidenceTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        keyStore = new KeyStore();
        String pem = Files.readString(KEYS.resolve("demo_public_key.pem"));
        keyStore.registerPemPublicKey(DEMO_KID, pem);
        verifier = new EvidenceTokenVerifier(keyStore);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static Path findRepoRoot() {
        // Walk up from the test class location to find the repo root (contains keys/)
        Path p = Paths.get(System.getProperty("user.dir"));
        while (p != null && !Files.exists(p.resolve("keys"))) {
            p = p.getParent();
        }
        return p != null ? p : Paths.get("..");
    }

    private String loadVector(String relativePath) throws IOException {
        return Files.readString(VECTORS.resolve(relativePath));
    }

    private Map<String, Object> parseVector(String relativePath) throws Exception {
        String json = loadVector(relativePath);
        return EvidenceTokenVerifier.JsonSimple.parse(json);
    }

    private String tokenFromVector(String relativePath) throws Exception {
        return (String) parseVector(relativePath).get("token");
    }

    // ── Valid token tests ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Valid minimal profile token verifies successfully")
    void validMinimalProfile() throws Exception {
        String token = tokenFromVector("valid/minimal_profile.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        // Legacy 'event' field is normalised to 'event_name' on the way through
        assertEquals("payment.initiated", result.getClaims().get("event_name"));
        assertEquals(1044L, ((Number) result.getClaims().get("seq")).longValue());
    }

    @Test
    @DisplayName("Valid standard profile token (with extended fields) verifies successfully")
    void validStandardProfile() throws Exception {
        String token = tokenFromVector("valid/standard_profile.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertEquals("payment", result.getClaims().get("scope"));
        assertEquals(1L, ((Number) result.getClaims().get("schema_v")).longValue());
    }

    @Test
    @DisplayName("Valid payment.retry token verifies successfully")
    void validPaymentRetry() throws Exception {
        String token = tokenFromVector("valid/payment_retry.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertEquals("payment.retry", result.getClaims().get("event_name"));
        assertEquals(1045L, ((Number) result.getClaims().get("seq")).longValue());
    }

    @Test
    @DisplayName("Verified result includes all required minimal profile claims")
    void allRequiredClaimsPresent() throws Exception {
        String token = tokenFromVector("valid/minimal_profile.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid());
        Map<String, Object> claims = result.getClaims();
        for (String field : new String[]{"eid", "did", "kid", "ts", "seq", "event_name", "tctx", "sig_ref"}) {
            assertTrue(claims.containsKey(field), "Missing claim: " + field);
        }
    }

    // ── Signature forged tests ─────────────────────────────────────────────────

    @Test
    @DisplayName("Token signed with an attacker key is rejected")
    void wrongKeySigRejected() throws Exception {
        String token = tokenFromVector("invalid/signature_forged/wrong_key.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("signature")
            || result.getReason().toLowerCase().contains("invalid"),
            "Expected signature rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token with a corrupted signature byte is rejected")
    void corruptedSignatureRejected() throws Exception {
        String token = tokenFromVector("invalid/signature_forged/corrupted_signature.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("Token with an empty signature segment is rejected")
    void emptySignatureRejected() throws Exception {
        String token = tokenFromVector("invalid/signature_forged/empty_signature.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("Token claiming an unregistered kid is rejected after re-fetch fails")
    void unknownKidRejected() throws Exception {
        String token = tokenFromVector("invalid/signature_forged/unknown_kid.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("kid")
            || result.getReason().toLowerCase().contains("unknown"),
            "Expected kid rejection, got: " + result.getReason());
    }

    // ── Algorithm confusion tests ──────────────────────────────────────────────

    @Test
    @DisplayName("Token claiming HS256 (symmetric) is rejected")
    void hs256Rejected() throws Exception {
        String token = tokenFromVector("invalid/algorithm_confusion/hs256_claim.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("algorithm")
            || result.getReason().toLowerCase().contains("alg"),
            "Expected algorithm rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token declaring alg=none is rejected immediately")
    void algNoneRejected() throws Exception {
        String token = tokenFromVector("invalid/algorithm_confusion/alg_none.json");
        VerificationResult result = verifier.verify(token, true);
        assertFalse(result.isValid());
    }

    // ── Freshness tests ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Token 1 hour old is rejected when freshness is enforced")
    void expiredTokenRejected() throws Exception {
        String token = tokenFromVector("invalid/expired_token/one_hour_old.json");
        // Create a new verifier instance without skip-freshness
        EvidenceTokenVerifier fresh = new EvidenceTokenVerifier(keyStore);
        VerificationResult result = fresh.verify(token, false);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("freshness"),
            "Expected freshness rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token dated 1 hour in the future is rejected")
    void futureDatedTokenRejected() throws Exception {
        String token = tokenFromVector("invalid/expired_token/future_dated.json");
        EvidenceTokenVerifier fresh = new EvidenceTokenVerifier(keyStore);
        VerificationResult result = fresh.verify(token, false);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("Expired token is accepted when freshness window is configured to accept it")
    void configurableFreshnessWindow() throws Exception {
        String token = tokenFromVector("invalid/expired_token/one_hour_old.json");
        // Use Long.MAX_VALUE: this static token was signed at a fixed past timestamp
        // and cannot be regenerated without the private key — any finite window would
        // eventually expire it. The test goal is verifying the window param is wired.
        EvidenceTokenVerifier wideWindow = new EvidenceTokenVerifier(keyStore, Long.MAX_VALUE);
        VerificationResult result = wideWindow.verify(token, false);
        assertTrue(result.isValid(), result.getReason());
    }

    // ── Replay detection tests ─────────────────────────────────────────────────

    @Test
    @DisplayName("Same valid token submitted twice: second submission is rejected as duplicate")
    void replayRejectedOnSecondSubmission() throws Exception {
        String token = tokenFromVector("invalid/replay_attack/duplicate_submission.json");
        VerificationResult first  = verifier.verify(token, true);
        VerificationResult second = verifier.verify(token, true);
        assertTrue(first.isValid(), "First submission should be valid");
        assertFalse(second.isValid(), "Second submission should be rejected as duplicate");
        assertTrue(second.getReason().toLowerCase().contains("duplicate"),
            "Expected duplicate rejection, got: " + second.getReason());
    }

    @Test
    @DisplayName("Distinct tokens (different event/seq) are not flagged as duplicates")
    void distinctTokensNotFlagged() throws Exception {
        String t1 = tokenFromVector("valid/minimal_profile.json");
        String t2 = tokenFromVector("valid/payment_retry.json");
        assertTrue(verifier.verify(t1, true).isValid());
        assertTrue(verifier.verify(t2, true).isValid());
    }

    // ── Missing field tests ────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"eid", "did", "kid", "ts", "seq", "event", "tctx", "sig_ref"})
    @DisplayName("Token missing a required field is rejected")
    void missingRequiredFieldRejected(String field) throws Exception {
        String token = tokenFromVector("invalid/missing_fields/missing_" + field + ".json");
        // Each missing-field test vector needs a fresh verifier (unique tokens)
        EvidenceTokenVerifier fresh = new EvidenceTokenVerifier(keyStore);
        VerificationResult result = fresh.verify(token, true);
        assertFalse(result.isValid(),
            "Expected REJECT for missing '" + field + "' but got VALID");
    }

    // ── Sequence regression tests ──────────────────────────────────────────────

    @Test
    @DisplayName("payment.retry with seq lower than prior attempt is rejected")
    void sequenceRegressionRejected() throws Exception {
        Map<String, Object> vector = parseVector("invalid/sequence_regression/seq_lower_than_prior.json");
        String token    = (String) vector.get("token");
        long   priorSeq = ((Number) vector.get("prior_seq")).longValue();

        // Seed the flow store with a prior attempt
        EvidenceTokenVerifier fresh = new EvidenceTokenVerifier(keyStore);
        Map<String, Object> priorClaims = new java.util.HashMap<>();
        priorClaims.put("did",   "dev-9f8e7d6c5b4a3c2d");
        priorClaims.put("tctx",  "tctx-7c4e9a2f1b8d3e56");
        priorClaims.put("event", "payment.initiated");
        priorClaims.put("seq",   priorSeq);
        priorClaims.put("boot_id", "f0e1d2c3-b4a5-6789-abcd-ef0123456789");
        fresh.seedFlowPrior("tctx-7c4e9a2f1b8d3e56", priorClaims);

        VerificationResult result = fresh.verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("sequence")
            || result.getReason().toLowerCase().contains("seq"),
            "Expected sequence rejection, got: " + result.getReason());
    }

    // ── Trust level tests ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Verified hardware attestation returns HARDWARE_BACKED trust")
    void hardwareBackedTrust() {
        Map<String, Object> record = new java.util.HashMap<>();
        Map<String, Object> att = new java.util.HashMap<>();
        att.put("device_state", "verified");
        record.put("attestation_ref", att);
        assertEquals(TrustLevel.HARDWARE_BACKED, EvidenceTokenVerifier.evaluateTrust(record));
    }

    @Test
    @DisplayName("Unknown attestation state returns EXECUTION_PROOF trust")
    void executionProofTrust() {
        Map<String, Object> record = new java.util.HashMap<>();
        Map<String, Object> att = new java.util.HashMap<>();
        att.put("device_state", "unknown");
        record.put("attestation_ref", att);
        assertEquals(TrustLevel.EXECUTION_PROOF, EvidenceTokenVerifier.evaluateTrust(record));
    }

    @Test
    @DisplayName("Failed attestation returns COMPROMISED_DEVICE trust")
    void compromisedDeviceTrust() {
        Map<String, Object> record = new java.util.HashMap<>();
        Map<String, Object> att = new java.util.HashMap<>();
        att.put("device_state", "failed");
        record.put("attestation_ref", att);
        assertEquals(TrustLevel.COMPROMISED_DEVICE, EvidenceTokenVerifier.evaluateTrust(record));
    }

    @Test
    @DisplayName("Missing attestation_ref returns SOFTWARE_LAYER trust")
    void softwareLayerTrustNoAttestation() {
        assertEquals(TrustLevel.SOFTWARE_LAYER, EvidenceTokenVerifier.evaluateTrust(new java.util.HashMap<>()));
    }

    // ── DER conversion tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("Raw 64-byte EC signature is correctly converted to DER format")
    void rawSigToDerConversion() {
        // Known R||S with high bits set to exercise 0x00 padding
        byte[] r = new byte[32]; r[0] = (byte) 0x80; // High bit set — needs 0x00 padding
        byte[] s = new byte[32]; s[0] = 0x01;
        byte[] raw = new byte[64];
        System.arraycopy(r, 0, raw, 0, 32);
        System.arraycopy(s, 0, raw, 32, 32);
        byte[] der = EvidenceTokenVerifier.rawEcSigToDer(raw);
        assertEquals(0x30, der[0] & 0xFF, "DER sequence tag");
        assertEquals(0x02, der[2] & 0xFF, "First integer tag");
        // R should have a 0x00 prefix since high bit is set
        assertEquals(0x00, der[4] & 0xFF, "High-bit padding byte for R");
    }

    // ── Trust level — additional cases ────────────────────────────────────────

    @Test
    @DisplayName("hardware_keystore device_state returns HARDWARE_BOUND trust")
    void hardwareBoundTrust() {
        Map<String, Object> record = new java.util.HashMap<>();
        Map<String, Object> att = new java.util.HashMap<>();
        att.put("device_state", "hardware_keystore");
        record.put("attestation_ref", att);
        assertEquals(TrustLevel.HARDWARE_BOUND, EvidenceTokenVerifier.evaluateTrust(record));
    }

    @Test
    @DisplayName("Unrecognised device_state falls back to SOFTWARE_LAYER (not a rejection)")
    void unknownDeviceStateFallsBackToSoftwareLayer() {
        Map<String, Object> record = new java.util.HashMap<>();
        Map<String, Object> att = new java.util.HashMap<>();
        att.put("device_state", "purple_unicorn");
        record.put("attestation_ref", att);
        assertEquals(TrustLevel.SOFTWARE_LAYER, EvidenceTokenVerifier.evaluateTrust(record));
    }

    // ── Utility tests ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("b64url decode handles url-safe '-' and '_' characters")
    void b64urlDecodeUrlSafeChars() throws Exception {
        // 0xFB 0xEF 0x12 encodes to "++8S" in standard Base64, "--8S" in Base64URL (no padding)
        byte[] expected = new byte[]{(byte) 0xFB, (byte) 0xEF, 0x12};
        byte[] decoded = EvidenceTokenVerifier.b64urlDecode("--8S");
        assertArrayEquals(expected, decoded);
    }

    @Test
    @DisplayName("b64url decode handles missing padding correctly")
    void b64urlDecodeRoundtrip() throws Exception {
        byte[] original = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(original);
        assertArrayEquals(original, EvidenceTokenVerifier.b64urlDecode(encoded));
    }

    // ── JsonSimple parser tests ────────────────────────────────────────────────

    @Test
    @DisplayName("JsonSimple parses nested objects correctly")
    void jsonSimpleParsesNestedObject() throws Exception {
        Map<String, Object> result = EvidenceTokenVerifier.JsonSimple.parse(
            "{\"outer\":{\"inner\":\"value\",\"num\":42}}");
        @SuppressWarnings("unchecked")
        Map<String, Object> outer = (Map<String, Object>) result.get("outer");
        assertEquals("value", outer.get("inner"));
        assertEquals(42L, ((Number) outer.get("num")).longValue());
    }

    @Test
    @DisplayName("JsonSimple parses boolean and null values correctly")
    void jsonSimpleParsesBooleanAndNull() throws Exception {
        Map<String, Object> result = EvidenceTokenVerifier.JsonSimple.parse(
            "{\"t\":true,\"f\":false,\"n\":null}");
        assertEquals(Boolean.TRUE,  result.get("t"));
        assertEquals(Boolean.FALSE, result.get("f"));
        assertNull(result.get("n"));
    }

    // ── Edge case / step 1 tests ───────────────────────────────────────────────

    @Test
    @DisplayName("Null token is rejected immediately")
    void nullTokenRejected() {
        VerificationResult result = verifier.verify(null, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("null"));
    }

    @Test
    @DisplayName("Token with only two segments (missing signature) is rejected")
    void twoSegmentTokenRejected() {
        VerificationResult result = verifier.verify("aaa.bbb", true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().contains("3"), result.getReason());
    }

    // ── SPEC normative requirements (crafted tokens) ───────────────────────────

    @Test
    @DisplayName("kid in JWS header that differs from kid in payload is rejected")
    void kidMismatchRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("kid", "some.other.kid.v2"); // payload kid ≠ header kid (DEMO_KID)
        String token = makeToken(claims, DEMO_KID);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid(), "Expected kid mismatch to be rejected");
        assertTrue(result.getReason().toLowerCase().contains("kid"),
            "Expected kid mention, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token with empty tctx is rejected")
    void tctxEmptyRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("tctx", "");
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("tctx"),
            "Expected tctx rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token with whitespace in tctx is rejected")
    void tctxWithWhitespaceRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("tctx", "has space");
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("tctx"),
            "Expected tctx rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token with invalid boot_id UUID is rejected")
    void bootIdInvalidUuidRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("boot_id", "not-a-valid-uuid");
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid());
        assertTrue(result.getReason().toLowerCase().contains("boot_id"),
            "Expected boot_id rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("Token with schema_v above supported version emits a warning but is valid")
    void schemaVUnknownEmitsWarning() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("schema_v", 999L);
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertTrue(result.getWarnings().stream().anyMatch(w -> w.contains("schema_v")),
            "Expected schema_v warning, got: " + result.getWarnings());
    }

    @Test
    @DisplayName("Token whose sig_ref lacks segment_id emits a backward-compat warning")
    void segmentIdAbsentEmitsWarning() throws Exception {
        Map<String, Object> sigRef = new java.util.HashMap<>();
        sigRef.put("ledger_seq", 9001L); // no segment_id
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("sig_ref", sigRef);
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertTrue(result.getWarnings().stream().anyMatch(w -> w.contains("segment_id")),
            "Expected segment_id warning, got: " + result.getWarnings());
    }

    @Test
    @DisplayName("Step 8 always adds a SOFTWARE_LAYER warning for inline token verification")
    void step8SoftwareLayerWarningPresent() throws Exception {
        String token = tokenFromVector("valid/minimal_profile.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid());
        assertTrue(result.getWarnings().stream().anyMatch(w -> w.contains("SOFTWARE_LAYER")),
            "Expected Step 8 warning, got: " + result.getWarnings());
    }

    // ── Legacy event field normalisation ──────────────────────────────────────

    @Test
    @DisplayName("Token with only legacy 'event' field has it normalised to 'event_name'")
    void legacyEventNormalisedToEventName() throws Exception {
        // makeToken with 'event' only (no 'event_name') via the static test vectors
        // The valid/minimal_profile.json uses the legacy 'event' field.
        String token = tokenFromVector("valid/minimal_profile.json");
        VerificationResult result = verifier.verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertNotNull(result.getClaims().get("event_name"),
            "event_name must be present after normalisation");
        assertTrue(result.getWarnings().stream().anyMatch(w -> w.contains("event")),
            "Expected normalisation warning, got: " + result.getWarnings());
    }

    @Test
    @DisplayName("When both 'event' and 'event_name' present, 'event_name' takes precedence")
    void eventNamePrecedenceOverEvent() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("event_name", "payment.authorised");
        claims.put("event",      "payment.initiated"); // lower-precedence field
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertTrue(result.isValid(), result.getReason());
        assertEquals("payment.authorised", result.getClaims().get("event_name"));
        assertTrue(result.getWarnings().stream().anyMatch(w -> w.contains("event_name")),
            "Expected precedence warning, got: " + result.getWarnings());
    }

    // ── BUG-1 non-regression: boolean/string masquerading as numeric fields ────

    @Test
    @DisplayName("BUG-1: seq=true (boolean) is rejected — Java Boolean does not extend Number")
    void booleanSeqRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("seq", Boolean.TRUE);
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid(), "seq=true must be rejected");
        assertTrue(result.getReason().toLowerCase().contains("seq"),
            "Expected seq rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("BUG-1: ts=true (boolean) is rejected")
    void booleanTsRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("ts", Boolean.TRUE);
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid(), "ts=true must be rejected");
        assertTrue(result.getReason().toLowerCase().contains("ts"),
            "Expected ts rejection, got: " + result.getReason());
    }

    @Test
    @DisplayName("seq as a JSON string (quoted number) is rejected")
    void stringSeqRejected() throws Exception {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("seq", "1044"); // String, not Number
        String token = makeToken(claims);
        VerificationResult result = new EvidenceTokenVerifier(keyStore).verify(token, true);
        assertFalse(result.isValid(), "seq as string must be rejected");
        assertTrue(result.getReason().toLowerCase().contains("seq"),
            "Expected seq rejection, got: " + result.getReason());
    }

    // ── Production + EvidenceRecordVerifier (SPEC.md) ────────────────────────────

    @Test
    @DisplayName("Production: oversized JWS compact string rejected")
    void oversizedJwsRejected() {
        VerificationResult r = verifier.verify("x".repeat(25000), true);
        assertFalse(r.isValid(), "expected REJECT for oversized token");
    }

    @Test
    @DisplayName("verifyTokenRecordBinding returns null when token and record align")
    void verifyTokenRecordBindingOk() {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("eid", "f1e2d3c4-b5a6-4789-0abc-def123456789");
        claims.put("did", "dev-9f8e7d6c5b4a3c2d");
        claims.put("tctx", "tctx-7c4e9a2f1b8d3e56");
        claims.put("seq", 1044L);
        Map<String, Object> sr = new java.util.HashMap<>();
        sr.put("ledger_seq", 1044L);
        sr.put("segment_id", 12L);
        claims.put("sig_ref", sr);
        Map<String, Object> record = new java.util.HashMap<>();
        record.put("eid", "f1e2d3c4-b5a6-4789-0abc-def123456789");
        record.put("device_id", "dev-9f8e7d6c5b4a3c2d");
        record.put("tctx", "tctx-7c4e9a2f1b8d3e56");
        record.put("seq", 1044L);
        Map<String, Object> cr = new java.util.HashMap<>();
        cr.put("ledger_seq", 1044L);
        cr.put("segment_id", 12L);
        record.put("chain_ref", cr);
        assertNull(EvidenceTokenVerifier.verifyTokenRecordBinding(claims, record));
    }

    @Test
    @DisplayName("EvidenceRecordVerifier verifies signed full_evidence_record.json")
    void recordVerifierFullExample() throws Exception {
        String json = Files.readString(EXAMPLES.resolve("full_evidence_record.json"));
        Map<String, Object> rec = EvidenceTokenVerifier.JsonSimple.parse(json);
        EvidenceRecordVerifier rv = new EvidenceRecordVerifier(keyStore);
        VerificationResult r = rv.verify(rec);
        assertTrue(r.isValid(), r.getReason());
    }

    @Test
    @DisplayName("EvidenceRecordVerifier verifyChain accepts uppercase hex event_hash")
    @SuppressWarnings("unchecked")
    void recordVerifierChainUppercaseHex() throws Exception {
        String j1 = Files.readString(EXAMPLES.resolve("demo_sequence/ledger_record_attempt1.json"));
        String j2 = Files.readString(EXAMPLES.resolve("demo_sequence/ledger_record_attempt2.json"));
        Map<String, Object> r1 = EvidenceTokenVerifier.JsonSimple.parse(j1);
        Map<String, Object> r2 = EvidenceTokenVerifier.JsonSimple.parse(j2);
        Map<String, Object> cr = (Map<String, Object>) r1.get("chain_ref");
        String eh = (String) cr.get("event_hash");
        cr.put("event_hash", eh.toUpperCase(Locale.ROOT));
        EvidenceRecordVerifier rv = new EvidenceRecordVerifier(keyStore);
        VerificationResult res = rv.verifyChain(List.of(r1, r2));
        assertTrue(res.isValid(), res.getReason());
    }

    // ── Token crafting helpers (for scenarios without static test vectors) ──────

    /**
     * Signs a token with the demo private key. Required claim fields are defaulted
     * if not supplied; callers override via the {@code claims} map.
     * Headers always use {@link #DEMO_KID} in the {@code kid} field — override
     * via the two-argument form to test kid-mismatch scenarios.
     */
    private String makeToken(Map<String, Object> claims) throws Exception {
        return makeToken(claims, DEMO_KID);
    }

    private String makeToken(Map<String, Object> claimsOverrides, String headerKid) throws Exception {
        Map<String, Object> c = new java.util.LinkedHashMap<>();

        // Required field defaults — caller overrides take priority
        c.put("eid",  claimsOverrides.getOrDefault("eid",  java.util.UUID.randomUUID().toString()));
        c.put("did",  claimsOverrides.getOrDefault("did",  "dev-0a1b2c3d4e5f6a7b"));
        c.put("kid",  claimsOverrides.getOrDefault("kid",  DEMO_KID));
        c.put("ts",   claimsOverrides.getOrDefault("ts",   System.currentTimeMillis()));
        c.put("tctx", claimsOverrides.getOrDefault("tctx", "tctx-test-9a8b7c6d"));
        Map<String, Object> defaultSigRef = new java.util.HashMap<>();
        defaultSigRef.put("ledger_seq", 9001L);
        defaultSigRef.put("segment_id", 1L);
        c.put("sig_ref", claimsOverrides.getOrDefault("sig_ref", defaultSigRef));

        // event / event_name — respect caller's choice; default to event_name
        if (claimsOverrides.containsKey("event_name")) {
            c.put("event_name", claimsOverrides.get("event_name"));
            if (claimsOverrides.containsKey("event")) c.put("event", claimsOverrides.get("event"));
        } else if (claimsOverrides.containsKey("event")) {
            c.put("event", claimsOverrides.get("event"));
        } else {
            c.put("event_name", "payment.initiated");
        }

        // seq — include as-is so callers can pass Boolean.TRUE for non-regression tests
        if (claimsOverrides.containsKey("seq")) {
            c.put("seq", claimsOverrides.get("seq"));
        } else {
            c.put("seq", 9001L);
        }

        // Any remaining extra claims (boot_id, schema_v, etc.)
        for (Map.Entry<String, Object> e : claimsOverrides.entrySet()) {
            c.putIfAbsent(e.getKey(), e.getValue());
        }

        String headerJson  = "{\"alg\":\"ES256\",\"kid\":\"" + headerKid + "\"}";
        String payloadJson = toJson(c);
        String hB64 = b64urlEncode(headerJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String pB64 = b64urlEncode(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String signingInput = hB64 + "." + pB64;

        // Load PKCS8 EC private key
        String pem = Files.readString(KEYS.resolve("demo_private_key.pem"));
        String stripped = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(stripped);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
        java.security.PrivateKey privateKey = kf.generatePrivate(
            new java.security.spec.PKCS8EncodedKeySpec(keyBytes));

        java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] rawSig = derToRawEcSig(sig.sign());
        return signingInput + "." + b64urlEncode(rawSig);
    }

    /** Converts a DER-encoded ECDSA signature (from Java's Signature API) to raw R||S (64 bytes). */
    private static byte[] derToRawEcSig(byte[] der) {
        // DER layout: 0x30 [totLen] 0x02 [rLen] [rBytes] 0x02 [sLen] [sBytes]
        int pos = 2; // skip 0x30 [totLen]
        int rLen = der[pos + 1] & 0xFF; pos += 2;
        byte[] rBytes = Arrays.copyOfRange(der, pos, pos + rLen); pos += rLen;
        int sLen = der[pos + 1] & 0xFF; pos += 2;
        byte[] sBytes = Arrays.copyOfRange(der, pos, pos + sLen);
        byte[] raw = new byte[64];
        copyToFixed32(rBytes, raw, 0);
        copyToFixed32(sBytes, raw, 32);
        return raw;
    }

    /** Copies src right-justified into a 32-byte slot at dst[dstOff], stripping DER sign padding. */
    private static void copyToFixed32(byte[] src, byte[] dst, int dstOff) {
        int srcOff = (src.length > 32 && src[0] == 0x00) ? 1 : 0;
        int len = src.length - srcOff;
        System.arraycopy(src, srcOff, dst, dstOff + (32 - len), len);
    }

    private static String b64urlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Minimal JSON serialiser for test claim maps. Handles String, Number, Boolean, Map, null. */
    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(e.getKey()).append("\":").append(toJsonValue(e.getValue()));
        }
        return sb.append("}").toString();
    }

    @SuppressWarnings("unchecked")
    private static String toJsonValue(Object v) {
        if (v == null)            return "null";
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Number)  return v.toString();
        if (v instanceof String)  return "\"" + v + "\"";
        if (v instanceof Map)     return toJson((Map<String, Object>) v);
        if (v instanceof java.util.List) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (java.util.List<?>) v) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJsonValue(item));
            }
            return sb.append("]").toString();
        }
        return "\"" + v + "\"";
    }
}
