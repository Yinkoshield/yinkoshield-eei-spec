// Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
// SPDX-License-Identifier: Apache-2.0
//
// YinkoShield Execution Evidence Infrastructure
// Evidence Token Verifier — Go Test Suite
//
// This is a reference implementation of the verification pipeline defined in SPEC.md.
// It demonstrates sovereign verification: no YinkoShield infrastructure required.
// Verification uses only the registered device public key.
//
// https://github.com/yinkoshield

package verifier

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test fixtures
var (
	repoRoot   string
	keysDir    string
	vectorsDir string
	examplesDir string
	demoKID    = "yinkoshield.device.sign.v1"
)

func init() {
	// Determine paths relative to test file
	wd, _ := os.Getwd()
	repoRoot = filepath.Join(wd, "..", "..")
	keysDir = filepath.Join(repoRoot, "keys")
	vectorsDir = filepath.Join(repoRoot, "test-vectors")
	examplesDir = filepath.Join(repoRoot, "examples")
}

func loadVector(t *testing.T, path string) map[string]interface{} {
	data, err := os.ReadFile(filepath.Join(vectorsDir, path))
	if err != nil {
		t.Fatalf("Failed to load vector %s: %v", path, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to parse vector %s: %v", path, err)
	}
	return result
}

func loadRecord(t *testing.T, path string) map[string]interface{} {
	data, err := os.ReadFile(filepath.Join(examplesDir, path))
	if err != nil {
		t.Fatalf("Failed to load record %s: %v", path, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to parse record %s: %v", path, err)
	}
	return result
}

func setupKeyStore(t *testing.T) *KeyStore {
	store := NewKeyStore()
	pubKeyPath := filepath.Join(keysDir, "demo_public_key.pem")
	if err := store.LoadPEM(demoKID, pubKeyPath); err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}
	return store
}

// ── Valid token tests ────────────────────────────────────────────────────────

func TestValidMinimalProfile(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "valid/minimal_profile.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusValid {
		t.Fatalf("Expected VALID, got %s: %s", result.Status, result.Reason)
	}
	if result.Claims.EventName != "payment.initiated" {
		t.Errorf("Expected event_name 'payment.initiated', got %s", result.Claims.EventName)
	}
	if result.Claims.Seq != 1044 {
		t.Errorf("Expected seq 1044, got %d", result.Claims.Seq)
	}
}

func TestValidStandardProfile(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "valid/standard_profile.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusValid {
		t.Fatalf("Expected VALID, got %s: %s", result.Status, result.Reason)
	}
	if result.Claims.Scope != "payment" {
		t.Errorf("Expected scope 'payment', got %s", result.Claims.Scope)
	}
	if result.Claims.SchemaV != 1 {
		t.Errorf("Expected schema_v 1, got %d", result.Claims.SchemaV)
	}
}

func TestValidPaymentRetry(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "valid/payment_retry.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusValid {
		t.Fatalf("Expected VALID, got %s: %s", result.Status, result.Reason)
	}
	if result.Claims.EventName != "payment.retry" {
		t.Errorf("Expected event_name 'payment.retry', got %s", result.Claims.EventName)
	}
}

func TestValidClaimsReturned(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "valid/minimal_profile.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Claims == nil {
		t.Fatal("Expected claims, got nil")
	}
	// After normalisation, at least one of EventName or Event must be set.
	eventSet := result.Claims.EventName != "" || result.Claims.Event != ""
	if result.Claims.Eid == "" || result.Claims.Did == "" || result.Claims.Kid == "" ||
		result.Claims.Ts == 0 || result.Claims.Seq == 0 || !eventSet ||
		result.Claims.Tctx == "" || result.Claims.SigRef == nil {
		t.Errorf("Missing required fields. Got: %+v", result.Claims)
	}
}

// ── Signature tests ──────────────────────────────────────────────────────────

func TestSignatureForgedWrongKey(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/signature_forged/wrong_key.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

func TestSignatureForgedCorrupted(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/signature_forged/corrupted_signature.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

func TestSignatureForgedEmpty(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/signature_forged/empty_signature.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

func TestSignatureForgedUnknownKID(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/signature_forged/unknown_kid.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

// ── Algorithm confusion tests ────────────────────────────────────────────────

func TestAlgorithmConfusionHS256(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/algorithm_confusion/hs256_claim.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

func TestAlgorithmConfusionNone(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/algorithm_confusion/alg_none.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

// ── Freshness tests ──────────────────────────────────────────────────────────

func TestFreshnessExpiredToken(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/expired_token/one_hour_old.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, false)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
}

func TestFreshnessFutureToken(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/expired_token/future_dated.json")
	token := vector["token"].(string)
	result := verifier.Verify(token, false)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT, got %s", result.Status)
	}
	if !strings.Contains(strings.ToLower(result.Reason), "freshness") {
		t.Errorf("Expected reason to mention 'freshness', got: %s", result.Reason)
	}
}

func TestFreshnessConfigurable(t *testing.T) {
	keyStore := setupKeyStore(t)
	vector := loadVector(t, "invalid/expired_token/one_hour_old.json")
	token := vector["token"].(string)

	// Decode the token's ts so the window is always wide enough for this static fixture,
	// regardless of how old the vector has become since it was generated.
	parts := strings.Split(token, ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode token payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("Failed to parse token claims: %v", err)
	}
	ts := int64(claims["ts"].(float64))
	ageMs := time.Now().UnixMilli() - ts

	wideVerifier := NewEvidenceTokenVerifier(keyStore, ageMs+60_000)
	result := wideVerifier.Verify(token, false)
	if result.Status != StatusValid {
		t.Errorf("Expected VALID with wide-enough window, got %s: %s", result.Status, result.Reason)
	}
}

// ── Replay tests ─────────────────────────────────────────────────────────────

func TestReplayDuplicate(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	vector := loadVector(t, "invalid/replay_attack/duplicate_submission.json")
	token := vector["token"].(string)
	first := verifier.Verify(token, true)
	if first.Status != StatusValid {
		t.Fatalf("First submission should be valid")
	}
	second := verifier.Verify(token, true)
	if second.Status != StatusReject {
		t.Errorf("Second submission should be rejected")
	}
}

func TestReplayDistinct(t *testing.T) {
	keyStore := setupKeyStore(t)
	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	v1 := loadVector(t, "valid/minimal_profile.json")
	v2 := loadVector(t, "valid/payment_retry.json")
	r1 := verifier.Verify(v1["token"].(string), true)
	r2 := verifier.Verify(v2["token"].(string), true)
	if r1.Status != StatusValid || r2.Status != StatusValid {
		t.Errorf("Distinct tokens should both be valid")
	}
}

// ── Missing fields tests ─────────────────────────────────────────────────────

func TestMissingField(t *testing.T) {
	fields := []string{"eid", "did", "kid", "ts", "seq", "event", "tctx", "sig_ref"} // missing_event.json has neither event nor event_name → REJECT
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			keyStore := setupKeyStore(t)
			verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
			vector := loadVector(t, "invalid/missing_fields/missing_"+field+".json")
			token := vector["token"].(string)
			result := verifier.Verify(token, true)
			if result.Status != StatusReject {
				t.Errorf("Expected REJECT for missing %s, got %s: %s", field, result.Status, result.Reason)
			}
		})
	}
}

// ── Sequence regression tests ────────────────────────────────────────────────

func TestSequenceRegression(t *testing.T) {
	keyStore := setupKeyStore(t)
	vector := loadVector(t, "invalid/sequence_regression/seq_lower_than_prior.json")
	priorSeq := int64(vector["prior_seq"].(float64))

	verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
	// Seed the flow store with a prior attempt
	priorClaims := &TokenClaims{
		Did:       "dev-9f8e7d6c5b4a3c2d",
		Tctx:      "tctx-7c4e9a2f1b8d3e56",
		EventName: "payment.initiated",
		Seq:       priorSeq,
		BootId:    "f0e1d2c3-b4a5-6789-abcd-ef0123456789",
	}
	verifier.flowStore["tctx-7c4e9a2f1b8d3e56"] = []*TokenClaims{priorClaims}

	token := vector["token"].(string)
	result := verifier.Verify(token, true)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for sequence regression, got %s", result.Status)
	}
}

// ── Chain integrity tests ────────────────────────────────────────────────────

func TestChainValid(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	r1 := loadRecord(t, "demo_sequence/ledger_record_attempt1.json")
	r2 := loadRecord(t, "demo_sequence/ledger_record_attempt2.json")
	result := recordVerifier.VerifyChain([]map[string]interface{}{r1, r2})
	if result.Status != StatusValid {
		t.Errorf("Expected VALID chain, got %s: %s", result.Status, result.Reason)
	}
}

func TestChainTamperedPrevHash(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	vector := loadVector(t, "invalid/broken_chain/tampered_prev_hash.json")
	r1 := loadRecord(t, "demo_sequence/ledger_record_attempt1.json")
	r2 := vector["record"].(map[string]interface{})
	result := recordVerifier.VerifyChain([]map[string]interface{}{r1, r2})
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for tampered prev_hash, got %s", result.Status)
	}
}

func TestChainTamperedContent(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	vector := loadVector(t, "invalid/broken_chain/event_hash_mismatch.json")
	record := vector["record"].(map[string]interface{})
	result := recordVerifier.VerifyChain([]map[string]interface{}{record})
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for tampered content, got %s", result.Status)
	}
}

func TestRecordSignatureValid(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")
	result := recordVerifier.Verify(record)
	if result.Status != StatusValid {
		t.Errorf("Expected VALID record, got %s: %s", result.Status, result.Reason)
	}
}

func TestAuthPaymentChain(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	rAuth := loadRecord(t, "chargeback_dispute/ledger_record_auth.json")
	rPay := loadRecord(t, "chargeback_dispute/ledger_record_payment.json")
	result := recordVerifier.VerifyChain([]map[string]interface{}{rAuth, rPay})
	if result.Status != StatusValid {
		t.Errorf("Expected VALID auth→payment chain, got %s: %s", result.Status, result.Reason)
	}
}

// ── Trust level tests ────────────────────────────────────────────────────────

func TestTrustHardwareBacked(t *testing.T) {
	record := map[string]interface{}{
		"attestation_ref": map[string]interface{}{
			"device_state": "verified",
		},
	}
	trust := EvaluateTrust(record)
	if trust != TrustHardwareBacked {
		t.Errorf("Expected hardware_backed, got %s", trust)
	}
}

func TestTrustExecutionProof(t *testing.T) {
	record := map[string]interface{}{
		"attestation_ref": map[string]interface{}{
			"device_state": "unknown",
		},
	}
	trust := EvaluateTrust(record)
	if trust != TrustExecutionProof {
		t.Errorf("Expected execution_proof, got %s", trust)
	}
}

func TestTrustCompromisedDevice(t *testing.T) {
	record := map[string]interface{}{
		"attestation_ref": map[string]interface{}{
			"device_state": "failed",
		},
	}
	trust := EvaluateTrust(record)
	if trust != TrustCompromisedDevice {
		t.Errorf("Expected compromised_device, got %s", trust)
	}
}

func TestTrustNoAttestation(t *testing.T) {
	record := map[string]interface{}{}
	trust := EvaluateTrust(record)
	if trust != TrustSoftwareLayer {
		t.Errorf("Expected software_layer, got %s", trust)
	}
}

func TestTrustHardwareBound(t *testing.T) {
	record := map[string]interface{}{
		"attestation_ref": map[string]interface{}{
			"device_state": "hardware_keystore",
		},
	}
	trust := EvaluateTrust(record)
	if trust != TrustHardwareBound {
		t.Errorf("Expected hardware_bound, got %s", trust)
	}
}

func TestTrustUnknownDeviceStateFallsBack(t *testing.T) {
	// Any device_state string not in the normative enum must fall through to software_layer.
	record := map[string]interface{}{
		"attestation_ref": map[string]interface{}{
			"device_state": "purple_unicorn",
		},
	}
	trust := EvaluateTrust(record)
	if trust != TrustSoftwareLayer {
		t.Errorf("Expected software_layer for unknown device_state, got %s", trust)
	}
}

func TestTrustFullRecord(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")
	result := recordVerifier.Verify(record)
	if result.TrustLevel != TrustHardwareBacked {
		t.Errorf("Expected hardware_backed trust, got %s", result.TrustLevel)
	}
}

// ── ts_source validation tests ───────────────────────────────────────────────

func TestRecordMissingTsSourceRejects(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")
	delete(record, "ts_source")
	result := recordVerifier.Verify(record)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for missing ts_source, got %s", result.Status)
	}
	if !strings.Contains(result.Reason, "ts_source") {
		t.Errorf("Expected reason to mention 'ts_source', got: %s", result.Reason)
	}
}

func TestRecordUnknownTsSourceProducesWarning(t *testing.T) {
	// A record with an unrecognised ts_source but no sig should reject on sig (not ts_source),
	// confirming the warning accumulation path doesn't short-circuit on unknown ts_source.
	fakeRecord := map[string]interface{}{
		"ts_source": "gps_satellite",
	}
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	result := recordVerifier.Verify(fakeRecord)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT (missing sig), got %s", result.Status)
	}
	if !strings.Contains(result.Reason, "sig") {
		t.Errorf("Expected reason to mention 'sig', got: %s", result.Reason)
	}
}

func TestRecordValidTsSourceAccepted(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")
	result := recordVerifier.Verify(record)
	if result.Status != StatusValid {
		t.Errorf("Expected VALID, got %s: %s", result.Status, result.Reason)
	}
}

// ── sig.algo validation tests ────────────────────────────────────────────────

func TestRecordSigAlgoNonES256Rejected(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")

	// Deep-copy via JSON round-trip and mutate sig.algo
	data, _ := json.Marshal(record)
	var tampered map[string]interface{}
	json.Unmarshal(data, &tampered) //nolint:errcheck
	sig := tampered["sig"].(map[string]interface{})
	sig["algo"] = "HS256"

	result := recordVerifier.Verify(tampered)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for non-ES256 sig.algo, got %s", result.Status)
	}
	if !strings.Contains(strings.ToLower(result.Reason), "algo") &&
		!strings.Contains(strings.ToLower(result.Reason), "algorithm") {
		t.Errorf("Expected reason to mention 'algo', got: %s", result.Reason)
	}
}

// ── chain_ref.hash_algo validation tests ─────────────────────────────────────

func TestChainWrongHashAlgoRejected(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")

	// Deep-copy and mutate chain_ref.hash_algo
	data, _ := json.Marshal(record)
	var tampered map[string]interface{}
	json.Unmarshal(data, &tampered) //nolint:errcheck
	chainRef := tampered["chain_ref"].(map[string]interface{})
	chainRef["hash_algo"] = "sha-512"

	result := recordVerifier.VerifyChain([]map[string]interface{}{tampered})
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for non-sha-256 hash_algo, got %s", result.Status)
	}
	if !strings.Contains(result.Reason, "hash_algo") && !strings.Contains(result.Reason, "sha-256") {
		t.Errorf("Expected reason to mention 'hash_algo' or 'sha-256', got: %s", result.Reason)
	}
}

// ── measured_at future-dating tests ──────────────────────────────────────────

func TestSignalFutureMeasuredAtRejected(t *testing.T) {
	keyStore := setupKeyStore(t)
	recordVerifier := NewEvidenceRecordVerifier(keyStore)
	record := loadRecord(t, "full_evidence_record.json")
	ts := record["ts"].(float64)
	futureTs := ts + 120_000 // 2 minutes after record ts — well above 5 s tolerance

	// Deep-copy and replace signals with a future-dated entry
	data, _ := json.Marshal(record)
	var tampered map[string]interface{}
	json.Unmarshal(data, &tampered) //nolint:errcheck
	tampered["signals"] = []interface{}{
		map[string]interface{}{
			"signal":             "device.integrity",
			"source":             "bootloader",
			"measured_at":        futureTs,
			"value":              "verified",
			"measurement_method": "hardware_attested",
		},
	}

	result := recordVerifier.Verify(tampered)
	if result.Status != StatusReject {
		t.Errorf("Expected REJECT for future-dated measured_at, got %s", result.Status)
	}
	if !strings.Contains(strings.ToLower(result.Reason), "measured_at") {
		t.Errorf("Expected reason to mention 'measured_at', got: %s", result.Reason)
	}
}

// ── Token-signing helper ──────────────────────────────────────────────────────

// validPayload is a base payload that passes all Step 4 validations.
// Merge with overrides to exercise specific validation paths.
var validPayload = map[string]interface{}{
	"eid":        "f1e2d3c4-b5a6-4789-0abc-def123456789",
	"did":        "dev-9f8e7d6c5b4a3c2d",
	"kid":        "yinkoshield.device.sign.v1",
	"ts":         float64(1709312400000),
	"seq":        float64(1044),
	"event_name": "payment.initiated",
	"tctx":       "tctx-7c4e9a2f1b8d3e56",
	"sig_ref": map[string]interface{}{
		"ledger_seq": float64(1044),
		"segment_id": float64(1),
	},
}

// mergePayload returns a shallow copy of validPayload with the given overrides applied.
func mergePayload(overrides map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(validPayload)+len(overrides))
	for k, v := range validPayload {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// makeToken signs payload with the demo private key and returns a compact JWS.
// Optional extraHeader maps are merged into the JWS header (for negative tests).
func makeToken(t *testing.T, payload map[string]interface{}, headerKid string, extraHeader ...map[string]interface{}) string {
	t.Helper()
	privKeyPath := filepath.Join(keysDir, "demo_private_key.pem")
	keyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		t.Fatalf("makeToken: read private key: %v", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		t.Fatal("makeToken: failed to decode PEM block")
	}
	privKeyRaw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("makeToken: parse private key: %v", err)
	}
	privKey, ok := privKeyRaw.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("makeToken: key is not EC")
	}

	header := map[string]interface{}{"alg": "ES256", "kid": headerKid, "typ": "JWS"}
	for _, ex := range extraHeader {
		for k, v := range ex {
			header[k] = v
		}
	}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := []byte(headerB64 + "." + payloadB64)
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatalf("makeToken: sign: %v", err)
	}

	// Pack r,s as two 32-byte big-endian integers
	rBytes := r.FillBytes(make([]byte, 32))
	sBytes := s.FillBytes(make([]byte, 32))
	rawSig := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(rawSig)
	return headerB64 + "." + payloadB64 + "." + sigB64
}

// ── Utility function unit tests ───────────────────────────────────────────────

func TestB64urlDecode(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantHex string
		wantErr bool
	}{
		{"3-byte no padding", base64.RawURLEncoding.EncodeToString([]byte("abc")), "616263", false},
		{"1-byte double padding", base64.RawURLEncoding.EncodeToString([]byte("a")), "61", false},
		{"2-byte single padding", base64.RawURLEncoding.EncodeToString([]byte("ab")), "6162", false},
		{"empty string", "", "", false},
		// url-safe '-' maps to standard '+'; 'AA+A' is valid base64 → 0x00, 0x20, 0x03
		{"url-safe minus char", base64.RawURLEncoding.EncodeToString([]byte{0xFB, 0xEF, 0x12}), "fbef12", false},
		{"invalid chars", "!@#$", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b64urlDecode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got none", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if tc.wantHex != "" {
				gotHex := fmt.Sprintf("%x", got)
				if gotHex != tc.wantHex {
					t.Errorf("got %s, want %s", gotHex, tc.wantHex)
				}
			}
		})
	}
}

func TestIsValidUUID(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid lowercase", "f1e2d3c4-b5a6-4789-0abc-def123456789", true},
		{"valid uppercase", "F1E2D3C4-B5A6-4789-0ABC-DEF123456789", true},
		{"valid mixed case", "f1e2D3c4-B5a6-4789-0AbC-dEf123456789", true},
		{"too short", "f1e2d3c4-b5a6-4789", false},
		{"no dashes", "f1e2d3c4b5a647890abcdef123456789", false},
		{"empty", "", false},
		{"non-hex chars", "f1e2d3c4-b5a6-4789-0abc-zzzzzzzzzzzz", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidUUID(tc.input)
			if got != tc.want {
				t.Errorf("isValidUUID(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestIsValidTctx(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid tctx", "tctx-7c4e9a2f1b8d3e56", true},
		{"empty", "", false},
		{"contains space", "tctx with space", false},
		{"contains tab", "tctx\twith\ttab", false},
		{"contains NUL", "tctx\x00", false},
		{"contains DEL (0x7F)", "tctx\x7f", false},
		{"C1 control 0x80", "tctx\x80", false},
		{"C1 control 0x9F", "tctx\x9f", false},
		{"first non-C1 0xA0 (NBSP)", "tctx\u00a0", true},
		{"printable special chars", "tctx!@#$%^&*()", true},
		{"single printable char", "x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidTctx(tc.input)
			if got != tc.want {
				t.Errorf("isValidTctx(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestDeepSortKeys(t *testing.T) {
	t.Run("flat object sorted", func(t *testing.T) {
		input := map[string]interface{}{"z": 1, "a": 2, "m": 3}
		sorted := deepSortKeys(input).(map[string]interface{})
		data, _ := json.Marshal(sorted)
		// JSON must have keys in alphabetical order
		want := `{"a":2,"m":3,"z":1}`
		if string(data) != want {
			t.Errorf("got %s, want %s", data, want)
		}
	})

	t.Run("nested objects sorted", func(t *testing.T) {
		input := map[string]interface{}{
			"z": map[string]interface{}{"y": 1, "b": 2},
			"a": 3,
		}
		sorted := deepSortKeys(input).(map[string]interface{})
		data, _ := json.Marshal(sorted)
		want := `{"a":3,"z":{"b":2,"y":1}}`
		if string(data) != want {
			t.Errorf("got %s, want %s", data, want)
		}
	})

	t.Run("array order preserved", func(t *testing.T) {
		input := map[string]interface{}{"arr": []interface{}{3, 1, 2}}
		sorted := deepSortKeys(input).(map[string]interface{})
		data, _ := json.Marshal(sorted)
		want := `{"arr":[3,1,2]}`
		if string(data) != want {
			t.Errorf("got %s, want %s", data, want)
		}
	})

	t.Run("scalar passthrough", func(t *testing.T) {
		if deepSortKeys(42) != 42 {
			t.Error("Expected 42 passthrough")
		}
		if deepSortKeys("hello") != "hello" {
			t.Error("Expected string passthrough")
		}
		if deepSortKeys(nil) != nil {
			t.Error("Expected nil passthrough")
		}
	})
}

func TestCanonicalJSON(t *testing.T) {
	input := map[string]interface{}{"z": 1, "a": 2}
	got, err := canonicalJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{"a":2,"z":1}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestMustMarshalECDSASig(t *testing.T) {
	t.Run("small r and s no high bit", func(t *testing.T) {
		r := new(big.Int).SetInt64(0x01)
		s := new(big.Int).SetInt64(0x02)
		der := mustMarshalECDSASig(r, s)
		// Must be valid DER SEQUENCE
		if der[0] != 0x30 {
			t.Errorf("Expected SEQUENCE tag 0x30, got 0x%02x", der[0])
		}
	})

	t.Run("r with high bit set gets 0x00 prefix", func(t *testing.T) {
		// r = 0xFF (high bit set) → DER integer needs 0x00 prefix
		r := new(big.Int).SetInt64(0xFF)
		s := new(big.Int).SetInt64(0x01)
		der := mustMarshalECDSASig(r, s)
		// Find r integer in DER: 0x30 [seq_len] 0x02 [r_len] [r_bytes...]
		rLen := int(der[3])
		if der[4] != 0x00 {
			t.Errorf("Expected 0x00 prefix for r with high bit set, rLen=%d, der=%x", rLen, der)
		}
	})

	t.Run("s with high bit set gets 0x00 prefix", func(t *testing.T) {
		r := new(big.Int).SetInt64(0x01)
		s := new(big.Int).SetInt64(0xFF)
		der := mustMarshalECDSASig(r, s)
		// Skip past r: 0x30 [seq_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes...]
		rLen := int(der[3])
		sOffset := 4 + rLen
		if der[sOffset] != 0x02 {
			t.Errorf("Expected INTEGER tag for s")
		}
		sLen := int(der[sOffset+1])
		if der[sOffset+2] != 0x00 {
			t.Errorf("Expected 0x00 prefix for s with high bit set, sLen=%d, der=%x", sLen, der)
		}
	})
}

func TestDeepCopy(t *testing.T) {
	original := map[string]interface{}{
		"a": map[string]interface{}{"b": 1},
	}
	copied := deepCopy(original).(map[string]interface{})
	// Mutate the copy's nested map — original must be unaffected
	copied["a"].(map[string]interface{})["b"] = 99
	if original["a"].(map[string]interface{})["b"] == 99 {
		t.Error("deepCopy did not produce an independent copy")
	}
}

func TestTrunc(t *testing.T) {
	cases := []struct {
		name  string
		s     string
		n     int
		want  string
	}{
		{"longer than n", "abcdefgh", 4, "abcd"},
		{"shorter than n", "abc", 10, "abc"},
		{"exactly n", "abcd", 4, "abcd"},
		{"empty string", "", 4, ""},
		{"n=0", "abc", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := trunc(tc.s, tc.n)
			if got != tc.want {
				t.Errorf("trunc(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

func TestVerificationResultOK(t *testing.T) {
	valid := &VerificationResult{Status: StatusValid}
	if !valid.OK() {
		t.Error("VALID result must be OK()")
	}
	rejected := &VerificationResult{Status: StatusReject, Reason: "test"}
	if rejected.OK() {
		t.Error("REJECT result must not be OK()")
	}
}

func TestKeyStoreBasic(t *testing.T) {
	t.Run("register and lookup", func(t *testing.T) {
		store := setupKeyStore(t)
		key := store.Lookup(demoKID)
		if key == nil {
			t.Error("Expected registered key, got nil")
		}
	})

	t.Run("lookup unknown returns nil", func(t *testing.T) {
		store := NewKeyStore()
		if store.Lookup("nonexistent.kid") != nil {
			t.Error("Expected nil for unknown kid")
		}
	})

	t.Run("refetch always returns nil", func(t *testing.T) {
		store := NewKeyStore()
		if store.Refetch("any.kid") != nil {
			t.Error("Base Refetch must always return nil")
		}
	})

	t.Run("multiple kids", func(t *testing.T) {
		store := setupKeyStore(t)
		pubKeyPath := filepath.Join(keysDir, "demo_public_key.pem")
		if err := store.LoadPEM("other.kid.v1", pubKeyPath); err != nil {
			t.Fatalf("LoadPEM failed: %v", err)
		}
		if store.Lookup("other.kid.v1") == nil {
			t.Error("Expected key for other.kid.v1")
		}
	})
}

// ── Non-regression tests for BUG-1: Go silent type coercion ─────────────────

func TestNonRegressionBoolAsInt(t *testing.T) {
	// In Go, json.Unmarshal into map[string]interface{} produces:
	//   JSON true  → bool(true)
	//   JSON false → bool(false)
	// The explicit .(float64) type assertion catches this and returns REJECT.

	tests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"seq=true", mergePayload(map[string]interface{}{"seq": true})},
		{"seq=false", mergePayload(map[string]interface{}{"seq": false})},
		{"ts=true", mergePayload(map[string]interface{}{"ts": true})},
		{"seq=string", mergePayload(map[string]interface{}{"seq": "1044"})},
		{"ts=string", mergePayload(map[string]interface{}{"ts": "1709312400000"})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyStore := setupKeyStore(t)
			verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
			token := makeToken(t, tc.payload, demoKID)
			result := verifier.Verify(token, true)
			if result.Status != StatusReject {
				t.Errorf("Expected REJECT for %s, got %s: %s", tc.name, result.Status, result.Reason)
			}
		})
	}
}

// ── SPEC normative security requirement tests ─────────────────────────────────

func TestSpecRequirements(t *testing.T) {
	t.Run("kid mismatch header vs payload rejected", func(t *testing.T) {
		// SPEC Step 4: kid in header and payload must be identical.
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"kid": "other.unknown.kid"})
		token := makeToken(t, payload, demoKID) // header kid = DEMO_KID, payload kid = other
		result := verifier.Verify(token, true)
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for kid mismatch, got %s: %s", result.Status, result.Reason)
		}
		reason := strings.ToLower(result.Reason)
		if !strings.Contains(reason, "kid") && !strings.Contains(reason, "mismatch") {
			t.Errorf("Expected 'kid' or 'mismatch' in reason, got: %s", result.Reason)
		}
	})

	t.Run("tctx empty rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"tctx": ""})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for empty tctx, got %s", result.Status)
		}
	})

	t.Run("tctx with whitespace rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"tctx": "tctx with space"})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for tctx with space, got %s", result.Status)
		}
	})

	t.Run("boot_id invalid uuid rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"boot_id": "not-a-uuid-at-all"})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for invalid boot_id, got %s", result.Status)
		}
	})

	t.Run("schema_v unknown produces warning not reject", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"schema_v": float64(99)})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusValid {
			t.Errorf("Expected VALID for unknown schema_v, got %s: %s", result.Status, result.Reason)
		}
		found := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "schema_v") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected schema_v warning, got warnings: %v", result.Warnings)
		}
	})

	t.Run("segment_id absent produces warning not reject", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		sigRef := map[string]interface{}{"ledger_seq": float64(1044)} // no segment_id
		payload := mergePayload(map[string]interface{}{"sig_ref": sigRef})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusValid {
			t.Errorf("Expected VALID for missing segment_id, got %s: %s", result.Status, result.Reason)
		}
		found := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "segment_id") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected segment_id warning, got: %v", result.Warnings)
		}
	})

	t.Run("event_name takes precedence over legacy event", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{
			"event_name": "payment.initiated",
			"event":      "legacy.ignored",
		})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusValid {
			t.Errorf("Expected VALID, got %s: %s", result.Status, result.Reason)
		}
		if result.Claims.EventName != "payment.initiated" {
			t.Errorf("Expected EventName='payment.initiated', got %q", result.Claims.EventName)
		}
	})

	t.Run("unknown extra fields accepted", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{
			"future_field":      "value",
			"another_new_field": float64(42),
		})
		token := makeToken(t, payload, demoKID)
		result := verifier.Verify(token, true)
		if result.Status != StatusValid {
			t.Errorf("Expected VALID for unknown fields, got %s: %s", result.Status, result.Reason)
		}
	})

	t.Run("malformed JWS two segments rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		verifier := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		result := verifier.Verify("header.payload", true)
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for 2-segment JWS, got %s", result.Status)
		}
	})
}

// ── verify_chain edge case tests ──────────────────────────────────────────────

func TestVerifyChainEdgeCases(t *testing.T) {
	t.Run("empty list returns valid", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		rv := NewEvidenceRecordVerifier(keyStore)
		result := rv.VerifyChain([]map[string]interface{}{})
		if result.Status != StatusValid {
			t.Errorf("Expected VALID for empty list, got %s: %s", result.Status, result.Reason)
		}
	})

	t.Run("out of order records sorted and valid", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		rv := NewEvidenceRecordVerifier(keyStore)
		r1 := loadRecord(t, "demo_sequence/ledger_record_attempt1.json")
		r2 := loadRecord(t, "demo_sequence/ledger_record_attempt2.json")
		// Supply in reverse order — VerifyChain MUST sort by seq internally.
		result := rv.VerifyChain([]map[string]interface{}{r2, r1})
		if result.Status != StatusValid {
			t.Errorf("Expected VALID for reversed records, got %s: %s", result.Status, result.Reason)
		}
	})

	t.Run("missing chain_ref rejected cleanly", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		rv := NewEvidenceRecordVerifier(keyStore)
		record := map[string]interface{}{"seq": float64(1), "ts": float64(1709312400000)}
		result := rv.VerifyChain([]map[string]interface{}{record})
		// chain_ref missing → chainRef is nil map → hash_algo = "" ≠ "sha-256" → REJECT
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for missing chain_ref, got %s: %s", result.Status, result.Reason)
		}
	})

	t.Run("missing event_hash rejected without panic (BUG-2 regression)", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		rv := NewEvidenceRecordVerifier(keyStore)
		record := map[string]interface{}{
			"seq": float64(1),
			"ts":  float64(1709312400000),
			"chain_ref": map[string]interface{}{
				"hash_algo": "sha-256",
				"prev_hash": strings.Repeat("0", 64),
				// event_hash intentionally absent
			},
		}
		// Must not panic; must return REJECT with a clean message
		result := rv.VerifyChain([]map[string]interface{}{record})
		if result.Status != StatusReject {
			t.Errorf("Expected REJECT for missing event_hash, got %s: %s", result.Status, result.Reason)
		}
	})
}

func TestProductionImplementation(t *testing.T) {
	t.Run("disallowed JWS header key rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		v := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		token := makeToken(t, mergePayload(nil), demoKID, map[string]interface{}{
			"jwk": map[string]interface{}{"kty": "EC", "crv": "P-256"},
		})
		result := v.Verify(token, true)
		if result.Status != StatusReject {
			t.Fatalf("expected REJECT, got %s", result.Status)
		}
	})

	t.Run("oversized token rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		v := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		result := v.Verify(strings.Repeat("x", 25000), true)
		if result.Status != StatusReject {
			t.Fatalf("expected REJECT, got %s", result.Status)
		}
	})

	t.Run("negative seq rejected", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		v := NewEvidenceTokenVerifier(keyStore, DefaultFreshnessWindowMs)
		payload := mergePayload(map[string]interface{}{"seq": float64(-1)})
		token := makeToken(t, payload, demoKID)
		result := v.Verify(token, true)
		if result.Status != StatusReject {
			t.Fatalf("expected REJECT, got %s", result.Status)
		}
	})

	t.Run("VerifyTokenRecordBinding OK", func(t *testing.T) {
		claims := &TokenClaims{
			Eid:       "f1e2d3c4-b5a6-4789-0abc-def123456789",
			Did:       "dev-9f8e7d6c5b4a3c2d",
			Tctx:      "tctx-7c4e9a2f1b8d3e56",
			Seq:       1044,
			SigRef:    map[string]interface{}{"ledger_seq": float64(1044), "segment_id": float64(12)},
		}
		record := map[string]interface{}{
			"eid":        claims.Eid,
			"device_id":  claims.Did,
			"tctx":       claims.Tctx,
			"seq":        float64(1044),
			"chain_ref":  map[string]interface{}{"ledger_seq": float64(1044), "segment_id": float64(12)},
		}
		if msg := VerifyTokenRecordBinding(claims, record); msg != "" {
			t.Fatal(msg)
		}
	})

	t.Run("verifyChain uppercase event_hash", func(t *testing.T) {
		keyStore := setupKeyStore(t)
		rv := NewEvidenceRecordVerifier(keyStore)
		r1orig := loadRecord(t, "demo_sequence/ledger_record_attempt1.json")
		r2 := loadRecord(t, "demo_sequence/ledger_record_attempt2.json")
		var r1 map[string]interface{}
		rb, err := json.Marshal(r1orig)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(rb, &r1); err != nil {
			t.Fatal(err)
		}
		cr := r1["chain_ref"].(map[string]interface{})
		eh := cr["event_hash"].(string)
		cr["event_hash"] = strings.ToUpper(eh)
		result := rv.VerifyChain([]map[string]interface{}{r1, r2})
		if result.Status != StatusValid {
			t.Fatalf("expected VALID: %s", result.Reason)
		}
	})
}
