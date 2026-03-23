// Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
// SPDX-License-Identifier: Apache-2.0
//
// YinkoShield Execution Evidence Infrastructure
// Evidence Token Verifier — Go Reference Implementation
//
// This is a reference implementation of the verification pipeline defined in SPEC.md.
// It demonstrates sovereign verification: no YinkoShield infrastructure required.
// Verification uses only the registered device public key.
//
// https://github.com/yinkoshield

// Package verifier implements the YinkoShield Evidence Token verification pipeline.
//
// Implements the 8-step verification pipeline defined in SPEC.md.
// No YinkoShield infrastructure required — verification uses only the registered device public key.
//
// Usage:
//
//	import verifier "github.com/yinkoshield/evidence-verifier-go"
//
//	store := verifier.NewKeyStore()
//	if err := store.LoadPEM("yinkoshield.device.sign.v1", "keys/demo_public_key.pem"); err != nil {
//	    log.Fatal(err)
//	}
//	v := verifier.NewEvidenceTokenVerifier(store, verifier.DefaultFreshnessWindowMs)
//	result := v.Verify(tokenString, false)
//	if result.OK() {
//	    log.Println("Event:", result.Claims.EventName)
//	}
package verifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	SupportedSchemaVersion   = 1
	DefaultFreshnessWindowMs = int64(300_000) // 5 minutes

	TrustHardwareBacked    = "hardware_backed"
	TrustHardwareBound     = "hardware_bound"
	TrustExecutionProof    = "execution_proof"
	TrustCompromisedDevice = "compromised_device"
	TrustSoftwareLayer     = "software_layer"

	StatusValid  = "VALID"
	StatusReject = "REJECT"
)

// Production limits — SPEC.md "Production implementation requirements"
const (
	maxJWSCompactUTF8Bytes    = 24_576
	maxJWSHeaderDecodedBytes  = 2_048
	maxJWSPayloadDecodedBytes = 12_288
	maxHeaderTypLength        = 128
	maxClaimKidLength         = 256
	maxClaimDidLength         = 128
	maxClaimTctxLength        = 256
	maxClaimEventNameLength   = 128
	maxJSONSafeInteger        = 9007199254740991 // 2^53 - 1
	minTSMsRecommended        = 1_000_000_000_000
)

var validAlgorithms = map[string]bool{"ES256": true}
var allowedJWSHeaderKeys = map[string]bool{"alg": true, "kid": true, "typ": true}

// Canonical field is event_name; legacy 'event' is accepted for backward compat. Checked separately.
var requiredMinimalFields = []string{"eid", "did", "kid", "ts", "seq", "tctx", "sig_ref"}

// ── Types ─────────────────────────────────────────────────────────────────────

// TokenClaims represents the parsed claims of a minimal or standard profile Evidence Token.
type TokenClaims struct {
	Eid     string                 `json:"eid"`
	Did     string                 `json:"did"`
	Kid     string                 `json:"kid"`
	Ts        int64                  `json:"ts"`
	Seq       int64                  `json:"seq"`
	EventName string                 `json:"event_name"` // canonical field name (SPEC.md v1.0+)
	Event     string                 `json:"event"`      // legacy field name; accepted for backward compat
	Tctx      string                 `json:"tctx"`
	SigRef  map[string]interface{} `json:"sig_ref"`
	SchemaV int                    `json:"schema_v,omitempty"`
	BootId  string                 `json:"boot_id,omitempty"`
	Scope   string                 `json:"scope,omitempty"`
	Net     map[string]interface{} `json:"net,omitempty"`
	Raw     map[string]interface{} `json:"-"`
}

// VerificationResult is returned by all verify methods.
type VerificationResult struct {
	Status     string
	Reason     string
	Claims     *TokenClaims
	TrustLevel string
	Warnings   []string
}

// OK returns true if the verification passed.
func (r *VerificationResult) OK() bool { return r.Status == StatusValid }

func rejectResult(reason string) *VerificationResult {
	return &VerificationResult{Status: StatusReject, Reason: reason}
}

func validResult(claims *TokenClaims, trust string, warnings []string) *VerificationResult {
	return &VerificationResult{Status: StatusValid, Claims: claims, TrustLevel: trust, Warnings: warnings}
}

// ── Key store ─────────────────────────────────────────────────────────────────

// KeyStore maps kid → *ecdsa.PublicKey.
type KeyStore struct {
	mu    sync.RWMutex
	store map[string]*ecdsa.PublicKey
}

// NewKeyStore creates an empty KeyStore.
func NewKeyStore() *KeyStore { return &KeyStore{store: make(map[string]*ecdsa.PublicKey)} }

// Register adds a public key for the given kid.
func (ks *KeyStore) Register(kid string, key *ecdsa.PublicKey) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.store[kid] = key
}

// LoadPEM parses an EC public key from a PEM file and registers it.
func (ks *KeyStore) LoadPEM(kid, pemPath string) error {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not an EC public key")
	}
	ks.Register(kid, ecKey)
	return nil
}

// Lookup returns the registered public key for kid, or nil if not found.
func (ks *KeyStore) Lookup(kid string) *ecdsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.store[kid]
}

// Refetch can be overridden in production to query the onboarding service on
// unknown kid (e.g. after key rotation). Returns nil if the kid is unknown.
func (ks *KeyStore) Refetch(kid string) *ecdsa.PublicKey { return nil }

// ── Utilities ─────────────────────────────────────────────────────────────────

func b64urlDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isValidTctx returns true if tctx is a non-empty printable string with no whitespace.
// tctx must carry at least 96 bits of entropy (≥24 hex chars for the random part).
func isValidTctx(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Reject invalid UTF-8: lone bytes in 0x80–0x9F would be silently replaced with
	// U+FFFD by range iteration, masking C1 control injection.
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		// Reject ASCII control chars (< 0x21), DEL (0x7F), and C1 controls (U+0080–U+009F).
		if c < 0x21 || c == 0x7F || (c >= 0x80 && c < 0xA0) {
			return false
		}
	}
	return true
}

// normalizeHex64 returns lowercase hex if s is exactly 64 hex digits.
func normalizeHex64(s string) (string, bool) {
	if len(s) != 64 {
		return "", false
	}
	var b strings.Builder
	b.Grow(64)
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(byte(c))
		case c >= 'a' && c <= 'f':
			b.WriteByte(byte(c))
		case c >= 'A' && c <= 'F':
			b.WriteByte(byte(c + ('a' - 'A')))
		default:
			return "", false
		}
	}
	return b.String(), true
}

func validateJWSHeaderProduction(h map[string]interface{}) string {
	for k := range h {
		if !allowedJWSHeaderKeys[k] {
			return fmt.Sprintf("Step 1: disallowed JWS header key(s) — %q is not permitted", k)
		}
	}
	if _, ok := h["alg"].(string); !ok {
		return "Step 1: JWS header 'alg' must be a string"
	}
	if _, ok := h["kid"].(string); !ok {
		return "Step 1: JWS header 'kid' must be a string"
	}
	if typ, ok := h["typ"].(string); ok {
		if len(typ) > maxHeaderTypLength {
			return fmt.Sprintf("Step 1: JWS header 'typ' exceeds max length %d", maxHeaderTypLength)
		}
	} else if _, has := h["typ"]; has {
		return "Step 1: JWS header 'typ' must be a string"
	}
	return ""
}

func productionValidateTokenStrings(claims *TokenClaims) string {
	if len(claims.Kid) > maxClaimKidLength {
		return fmt.Sprintf("Step 4: 'kid' exceeds max length %d", maxClaimKidLength)
	}
	if len(claims.Did) > maxClaimDidLength {
		return fmt.Sprintf("Step 4: 'did' exceeds max length %d", maxClaimDidLength)
	}
	if len(claims.Tctx) > maxClaimTctxLength {
		return fmt.Sprintf("Step 4: 'tctx' exceeds max length %d", maxClaimTctxLength)
	}
	if len(claims.EventName) > maxClaimEventNameLength {
		return fmt.Sprintf("Step 4: 'event_name' exceeds max length %d", maxClaimEventNameLength)
	}
	return ""
}

func productionValidateInt64(name string, v int64) string {
	if v < 0 || v > maxJSONSafeInteger {
		return fmt.Sprintf("Step 4: '%s' out of allowed range [0, %d]", name, maxJSONSafeInteger)
	}
	return ""
}

func floatIsIntegerJSON(f float64) bool {
	return f == math.Trunc(f) && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func productionValidateSigRefInts(sigRef map[string]interface{}) string {
	ls, ok := sigRef["ledger_seq"].(float64)
	if !ok || !floatIsIntegerJSON(ls) {
		return "Step 4: 'sig_ref.ledger_seq' must be a numeric integer"
	}
	if msg := productionValidateInt64("sig_ref.ledger_seq", int64(ls)); msg != "" {
		return msg
	}
	if _, has := sigRef["segment_id"]; has {
		sid, ok := sigRef["segment_id"].(float64)
		if !ok || !floatIsIntegerJSON(sid) {
			return "Step 4: 'sig_ref.segment_id' must be a numeric integer"
		}
		if msg := productionValidateInt64("sig_ref.segment_id", int64(sid)); msg != "" {
			return msg
		}
	}
	return ""
}

// VerifyTokenRecordBinding checks that verified token claims match a fetched Evidence Record (SPEC).
// Returns empty string if OK, otherwise a rejection reason. Does not verify signatures.
func VerifyTokenRecordBinding(claims *TokenClaims, record map[string]interface{}) string {
	if claims.Eid != record["eid"] {
		return "Binding: token eid does not match record eid"
	}
	if claims.Did != record["device_id"] {
		return "Binding: token did does not match record device_id"
	}
	if claims.Tctx != record["tctx"] {
		return "Binding: token tctx does not match record tctx"
	}
	rs, ok1 := record["seq"].(float64)
	if !ok1 || !floatIsIntegerJSON(rs) || int64(rs) != claims.Seq {
		return "Binding: token seq does not match record seq"
	}
	sigRef := claims.SigRef
	if sigRef == nil {
		return "Binding: token sig_ref missing"
	}
	cr, ok := record["chain_ref"].(map[string]interface{})
	if !ok || cr == nil {
		return "Binding: record chain_ref missing or not an object"
	}
	lsTok, ok := sigRef["ledger_seq"].(float64)
	if !ok || !floatIsIntegerJSON(lsTok) {
		return "Binding: invalid token sig_ref.ledger_seq"
	}
	lsRec, ok := cr["ledger_seq"].(float64)
	if !ok || !floatIsIntegerJSON(lsRec) || int64(lsTok) != int64(lsRec) {
		return "Binding: sig_ref.ledger_seq does not match chain_ref.ledger_seq"
	}
	_, tokSeg := sigRef["segment_id"]
	_, recSeg := cr["segment_id"]
	if tokSeg && recSeg {
		ts, ok := sigRef["segment_id"].(float64)
		rs, ok2 := cr["segment_id"].(float64)
		if !ok || !ok2 || !floatIsIntegerJSON(ts) || !floatIsIntegerJSON(rs) || int64(ts) != int64(rs) {
			return "Binding: sig_ref.segment_id does not match chain_ref.segment_id"
		}
	}
	return ""
}

// canonicalJSON produces a deep-key-sorted, compact JSON representation.
// This matches the signing device's canonical form (Python json.dumps sort_keys=True,
// separators=(',', ':') — see SPEC.md § Canonical JSON).
func canonicalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(deepSortKeys(v))
}

// deepSortKeys recursively sorts all object keys at every depth, producing a
// deterministic JSON structure regardless of original key order.
func deepSortKeys(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]interface{}, len(val))
		for _, k := range keys {
			out[k] = deepSortKeys(val[k])
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = deepSortKeys(item)
		}
		return out
	default:
		return v
	}
}

// ── Trust evaluation ──────────────────────────────────────────────────────────

// EvaluateTrust returns the trust level derived from a fetched Evidence Record.
// Call this after retrieving the record via sig_ref.ledger_seq.
func EvaluateTrust(record map[string]interface{}) string {
	attRaw, ok := record["attestation_ref"]
	if !ok || attRaw == nil {
		return TrustSoftwareLayer
	}
	att, ok := attRaw.(map[string]interface{})
	if !ok {
		return TrustSoftwareLayer
	}
	switch att["device_state"] {
	case "verified":
		return TrustHardwareBacked
	case "hardware_keystore":
		return TrustHardwareBound
	case "unknown":
		return TrustExecutionProof
	case "failed":
		return TrustCompromisedDevice
	default:
		return TrustSoftwareLayer
	}
}

// ── Evidence Token Verifier ───────────────────────────────────────────────────

// EvidenceTokenVerifier implements the 8-step token verification pipeline.
type EvidenceTokenVerifier struct {
	KeyStore          *KeyStore
	FreshnessWindowMs int64
	dedupMu           sync.Mutex
	dedupStore        map[string]int64 // key → expiry unix ms; entries pruned on access
	flowMu            sync.Mutex
	flowStore         map[string][]*TokenClaims
}

// NewEvidenceTokenVerifier creates a verifier with the specified freshness window.
// Pass DefaultFreshnessWindowMs for the recommended 5-minute window.
func NewEvidenceTokenVerifier(ks *KeyStore, freshnessWindowMs int64) *EvidenceTokenVerifier {
	return &EvidenceTokenVerifier{
		KeyStore:          ks,
		FreshnessWindowMs: freshnessWindowMs,
		dedupStore:        make(map[string]int64),
		flowStore:         make(map[string][]*TokenClaims),
	}
}

// Verify runs the full 8-step pipeline. Set skipFreshness=true only for static test fixtures.
func (v *EvidenceTokenVerifier) Verify(token string, skipFreshness bool) *VerificationResult {
	warnings := []string{}
	token = strings.TrimSpace(token)
	if len(token) > maxJWSCompactUTF8Bytes {
		return rejectResult(fmt.Sprintf(
			"Step 1: JWS compact token exceeds maximum size (%d UTF-8 bytes)", maxJWSCompactUTF8Bytes,
		))
	}

	// ── Step 1: Parse JWS ─────────────────────────────────────────────────
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return rejectResult("Step 1: expected 3 dot-separated JWS segments")
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	headerBytes, err := b64urlDecode(headerB64)
	if err != nil {
		return rejectResult(fmt.Sprintf("Step 1: header decode error: %v", err))
	}
	if len(headerBytes) > maxJWSHeaderDecodedBytes {
		return rejectResult(fmt.Sprintf(
			"Step 1: JWS header exceeds maximum decoded size (%d bytes)", maxJWSHeaderDecodedBytes,
		))
	}
	payloadBytes, err := b64urlDecode(payloadB64)
	if err != nil {
		return rejectResult(fmt.Sprintf("Step 1: payload decode error: %v", err))
	}
	if len(payloadBytes) > maxJWSPayloadDecodedBytes {
		return rejectResult(fmt.Sprintf(
			"Step 1: JWS payload exceeds maximum decoded size (%d bytes)", maxJWSPayloadDecodedBytes,
		))
	}

	var jwsHeader map[string]interface{}
	if err := json.Unmarshal(headerBytes, &jwsHeader); err != nil {
		return rejectResult(fmt.Sprintf("Step 1: header parse error: %v", err))
	}
	if msg := validateJWSHeaderProduction(jwsHeader); msg != "" {
		return rejectResult(msg)
	}
	algRaw, ok := jwsHeader["alg"]
	if !ok {
		return rejectResult("Step 1: missing 'alg' in JWS header")
	}
	kidRaw, ok := jwsHeader["kid"]
	if !ok {
		return rejectResult("Step 1: missing 'kid' in JWS header")
	}

	alg, _ := algRaw.(string)
	kid, _ := kidRaw.(string)
	if !validAlgorithms[alg] {
		return rejectResult(fmt.Sprintf("Step 1: unsupported algorithm '%s'. Accepted: ES256", alg))
	}

	// ── Step 2: Resolve signing key ──────────────────────────────────────
	publicKey := v.KeyStore.Lookup(kid)
	if publicKey == nil {
		publicKey = v.KeyStore.Refetch(kid)
		if publicKey == nil {
			return rejectResult(fmt.Sprintf("Step 2: unknown kid '%s'. Device not registered or key rotation not reconciled.", kid))
		}
		v.KeyStore.Register(kid, publicKey)
	}

	// ── Step 3: Verify signature ─────────────────────────────────────────
	rawSig, err := b64urlDecode(sigB64)
	if err != nil {
		return rejectResult(fmt.Sprintf("Step 3: signature decode error: %v", err))
	}
	if len(rawSig) != 64 {
		return rejectResult(fmt.Sprintf("Step 3: invalid ES256 signature length (%d bytes, expected 64)", len(rawSig)))
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	signingInput := []byte(headerB64 + "." + payloadB64)
	digest := sha256.Sum256(signingInput)
	if !ecdsa.VerifyASN1(publicKey, digest[:], mustMarshalECDSASig(r, s)) {
		return rejectResult("Step 3: invalid signature")
	}

	// ── Step 4: Parse and validate claims ────────────────────────────────
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return rejectResult(fmt.Sprintf("Step 4 (parse claims): %v", err))
	}
	for _, field := range requiredMinimalFields {
		if _, exists := rawClaims[field]; !exists {
			return rejectResult(fmt.Sprintf("Step 4: missing required field '%s'", field))
		}
	}

	// Normalise event field: spec uses 'event_name'; legacy tokens use 'event'.
	if _, hasEventName := rawClaims["event_name"]; !hasEventName {
		if legacyEvent, hasEvent := rawClaims["event"]; hasEvent {
			rawClaims["event_name"] = legacyEvent
			warnings = append(warnings, "Step 4: legacy 'event' field found; use 'event_name' in new implementations.")
		} else {
			return rejectResult("Step 4: missing required field 'event_name' (or legacy 'event')")
		}
	}

	// Step 4: Explicit numeric type checks — JSON numbers unmarshal to float64.
	// Unlike Python/JS which check types after struct parsing, Go's json.Unmarshal
	// silently coerces mismatched types (e.g., a string seq → 0). Check raw map first.
	seqF, ok := rawClaims["seq"].(float64)
	if !ok {
		return rejectResult("Step 4: 'seq' must be a numeric integer")
	}
	tsF, ok := rawClaims["ts"].(float64)
	if !ok {
		return rejectResult("Step 4: 'ts' must be a numeric integer")
	}
	if !floatIsIntegerJSON(seqF) || !floatIsIntegerJSON(tsF) {
		return rejectResult("Step 4: 'seq' and 'ts' must be integral JSON numbers")
	}

	claims := &TokenClaims{Raw: rawClaims}
	claimsBytes, _ := json.Marshal(rawClaims)
	json.Unmarshal(claimsBytes, claims) //nolint:errcheck // rawClaims already validated above

	// Q1: kid in JWS header and payload must be identical — both are signed material,
	// so a mismatch is structurally impossible in a legitimate token.
	if claims.Kid != kid {
		return rejectResult(fmt.Sprintf("Step 4: kid mismatch — header kid='%s' != payload kid='%s'", kid, claims.Kid))
	}

	// Q6: tctx must be a non-empty printable string with no whitespace.
	if !isValidTctx(claims.Tctx) {
		return rejectResult("Step 4: 'tctx' must be a non-empty printable string with no whitespace")
	}

	if !isValidUUID(claims.Eid) {
		return rejectResult("Step 4: 'eid' is not a valid UUID")
	}
	// Validate sig_ref is an object containing ledger_seq
	sigRefRaw, _ := rawClaims["sig_ref"].(map[string]interface{})
	if sigRefRaw == nil {
		return rejectResult("Step 4: 'sig_ref' must be an object")
	}
	if _, hasLedgerSeq := sigRefRaw["ledger_seq"]; !hasLedgerSeq {
		return rejectResult("Step 4: 'sig_ref' must contain 'ledger_seq'")
	}
	// segment_id is required for new tokens; v1.0 signed tokens predate this requirement.
	// Warn but do not reject to maintain backward compatibility.
	if _, hasSegmentID := sigRefRaw["segment_id"]; !hasSegmentID {
		warnings = append(warnings,
			"Step 4: sig_ref.segment_id is absent. "+
				"New token implementations MUST include segment_id. "+
				"This token predates SPEC v1.1 and is accepted for backward compatibility.",
		)
	}

	if claims.BootId != "" && !isValidUUID(claims.BootId) {
		return rejectResult("Step 4: 'boot_id' is not a valid UUID")
	}
	if claims.SchemaV != 0 && claims.SchemaV != SupportedSchemaVersion {
		warnings = append(warnings, fmt.Sprintf(
			"Step 4: schema_v=%d > supported=%d. Processing known fields only.",
			claims.SchemaV, SupportedSchemaVersion,
		))
	}

	if msg := productionValidateInt64("ts", claims.Ts); msg != "" {
		return rejectResult(msg)
	}
	if claims.Ts < minTSMsRecommended {
		return rejectResult(fmt.Sprintf(
			"Step 4: 'ts' is below minimum allowed (%d ms epoch)", minTSMsRecommended,
		))
	}
	if msg := productionValidateInt64("seq", claims.Seq); msg != "" {
		return rejectResult(msg)
	}
	if msg := productionValidateTokenStrings(claims); msg != "" {
		return rejectResult(msg)
	}
	if msg := productionValidateSigRefInts(sigRefRaw); msg != "" {
		return rejectResult(msg)
	}

	// ── Step 5: Freshness ─────────────────────────────────────────────────
	if !skipFreshness {
		nowMs := time.Now().UnixMilli()
		ageMs := nowMs - claims.Ts
		if ageMs < 0 {
			ageMs = -ageMs
		}
		if ageMs > v.FreshnessWindowMs {
			return rejectResult(fmt.Sprintf(
				"Step 5: token outside freshness window (age=%dms, window=%dms)", ageMs, v.FreshnessWindowMs,
			))
		}
	}

	// ── Step 6: Deduplicate ───────────────────────────────────────────────
	// Use NUL byte (\x00) as separator — tctx is printable and can contain ':', so a colon
	// separator creates a collision class. NUL cannot appear in any valid printable field.
	dedupKey := fmt.Sprintf("%s\x00%s\x00%s\x00%d", claims.Did, claims.Tctx, claims.EventName, claims.Seq)
	// Expiry: 2 × freshness window from insertion time (SPEC: "MAY be pruned after
	// 2 × freshnessWindowMs has elapsed since insertion"). Must be insertion-based
	// so static test fixtures with historical ts values don't expire immediately.
	nowMsDedup := time.Now().UnixMilli()
	dedupExpiryMs := nowMsDedup + 2*v.FreshnessWindowMs
	v.dedupMu.Lock()
	// Prune expired entries to bound memory growth.
	for k, exp := range v.dedupStore {
		if exp <= nowMsDedup {
			delete(v.dedupStore, k)
		}
	}
	_, isDup := v.dedupStore[dedupKey]
	if !isDup {
		v.dedupStore[dedupKey] = dedupExpiryMs
	}
	v.dedupMu.Unlock()
	if isDup {
		return rejectResult(fmt.Sprintf(
			"Step 6: duplicate token (did=%s, tctx=%s, event_name=%s, seq=%d)",
			claims.Did, claims.Tctx, claims.EventName, claims.Seq,
		))
	}

	// ── Step 7: Retry correlation ─────────────────────────────────────────
	retryEvents := map[string]bool{
		"payment.retry": true, "pos.txn.retry": true, "login.retry": true, "auth.retry": true,
	}
	// Hold the lock across the full read-check-write to prevent TOCTOU race.
	v.flowMu.Lock()
	if retryEvents[claims.EventName] {
		prior := v.flowStore[claims.Tctx]
		if len(prior) > 0 {
			maxSeq := int64(0)
			for _, p := range prior {
				if p.Seq > maxSeq {
					maxSeq = p.Seq
				}
			}
			if claims.Seq <= maxSeq {
				v.flowMu.Unlock()
				return rejectResult(fmt.Sprintf(
					"Step 7: sequence regression in retry. seq=%d <= prior max=%d", claims.Seq, maxSeq,
				))
			}
			if prior[0].BootId != "" && claims.BootId != "" && prior[0].BootId != claims.BootId {
				warnings = append(warnings,
					"Step 7: boot_id changed mid-flow. May indicate device reboot between retries — review policy.",
				)
			}
		}
	}
	v.flowStore[claims.Tctx] = append(v.flowStore[claims.Tctx], claims)
	v.flowMu.Unlock()

	// ── Step 8: Trust level ───────────────────────────────────────────────
	warnings = append(warnings,
		"Step 8: ledger record not fetched. Trust level is software_layer. "+
			"Fetch the full Evidence Record via sig_ref.ledger_seq for dispute-grade trust.",
	)

	return validResult(claims, TrustSoftwareLayer, warnings)
}

// mustMarshalECDSASig marshals r,s big integers into a DER-encoded ECDSA signature.
func mustMarshalECDSASig(r, s *big.Int) []byte {
	rb, sb := r.Bytes(), s.Bytes()
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0x00}, rb...)
	}
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0x00}, sb...)
	}
	seqLen := 2 + len(rb) + 2 + len(sb)
	der := make([]byte, 0, 2+seqLen)
	der = append(der, 0x30, byte(seqLen))
	der = append(der, 0x02, byte(len(rb)))
	der = append(der, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)
	return der
}

// ── Evidence Record Verifier ──────────────────────────────────────────────────

// EvidenceRecordVerifier verifies device-signed Evidence Records and hash chains.
type EvidenceRecordVerifier struct {
	KeyStore *KeyStore
}

// NewEvidenceRecordVerifier creates an EvidenceRecordVerifier backed by the given key store.
func NewEvidenceRecordVerifier(ks *KeyStore) *EvidenceRecordVerifier {
	return &EvidenceRecordVerifier{KeyStore: ks}
}

var validTsSources = map[string]bool{"secure_clock": true, "ntp": true, "rtc": true}

// signalClockSkewToleranceMs is the maximum number of milliseconds a signal's
// measured_at may exceed the record's ts before the record is rejected.
const signalClockSkewToleranceMs = int64(5_000)

// Verify checks the device signature on a ledger Evidence Record.
func (rv *EvidenceRecordVerifier) Verify(record map[string]interface{}) *VerificationResult {
	var warnings []string

	// ts_source: MUST be present; unknown values are warnings not rejections.
	tsSourceRaw, hasTsSource := record["ts_source"]
	if !hasTsSource || tsSourceRaw == nil {
		return rejectResult("Record missing required 'ts_source' field")
	}
	tsSource, _ := tsSourceRaw.(string)
	if !validTsSources[tsSource] {
		warnings = append(warnings, fmt.Sprintf(
			"Record ts_source='%s' is not a recognised value (ntp, rtc, secure_clock). Treat timestamp with caution.",
			tsSource,
		))
	}

	// M6: validate measured_at on all signals — must not exceed record ts + tolerance
	if recordTs, ok := record["ts"].(float64); ok {
		if signals, ok := record["signals"].([]interface{}); ok {
			for _, sigEntryRaw := range signals {
				sigEntry, _ := sigEntryRaw.(map[string]interface{})
				if sigEntry == nil {
					continue
				}
				measuredAt, hasMeasuredAt := sigEntry["measured_at"].(float64)
				if hasMeasuredAt && int64(measuredAt) > int64(recordTs)+signalClockSkewToleranceMs {
					sigName, _ := sigEntry["signal"].(string)
					return rejectResult(fmt.Sprintf(
						"Record signal '%s' has measured_at=%.0f which exceeds record ts=%.0f + tolerance=%dms. "+
							"A signal cannot be measured after the event it is reported with.",
						sigName, measuredAt, recordTs, signalClockSkewToleranceMs,
					))
				}
			}
		}
	}

	sigRaw, ok := record["sig"]
	if !ok {
		return rejectResult("Record missing 'sig' field")
	}
	sigObj, ok := sigRaw.(map[string]interface{})
	if !ok {
		return rejectResult("Record 'sig' is not an object")
	}

	// S1: reject non-ES256 algo before attempting signature verification
	algo, _ := sigObj["algo"].(string)
	if algo != "ES256" {
		return rejectResult(fmt.Sprintf("Record sig.algo must be 'ES256'; got '%s'", algo))
	}

	keyID, _ := sigObj["key_id"].(string)
	if keyID == "" {
		return rejectResult("Record sig missing 'key_id'")
	}
	sigValueB64, _ := sigObj["value"].(string)
	if sigValueB64 == "" {
		return rejectResult("Record sig missing 'value'")
	}

	publicKey := rv.KeyStore.Lookup(keyID)
	if publicKey == nil {
		publicKey = rv.KeyStore.Refetch(keyID)
		if publicKey == nil {
			return rejectResult(fmt.Sprintf("Unknown key_id '%s'", keyID))
		}
		rv.KeyStore.Register(keyID, publicKey)
	}

	// Canonical record: all fields except 'sig', deep-sorted
	recordNoSig := make(map[string]interface{}, len(record)-1)
	for k, v := range record {
		if k != "sig" {
			recordNoSig[k] = v
		}
	}
	canonical, err := canonicalJSON(recordNoSig)
	if err != nil {
		return rejectResult(fmt.Sprintf("Canonical JSON error: %v", err))
	}

	rawSig, err := b64urlDecode(sigValueB64)
	if err != nil {
		return rejectResult(fmt.Sprintf("Signature decode error: %v", err))
	}
	if len(rawSig) != 64 {
		return rejectResult(fmt.Sprintf("Record sig: invalid ES256 signature length (%d bytes, expected 64)", len(rawSig)))
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	digest := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(publicKey, digest[:], mustMarshalECDSASig(r, s)) {
		return rejectResult("Record signature invalid")
	}

	return validResult(nil, EvaluateTrust(record), warnings)
}

// VerifyChain verifies hash-chain integrity across a sequence of Evidence Records.
// Records may be provided in any order; they are sorted by seq ascending internally.
//
// NOTE: This method checks chain integrity only (hash linkage and event_hash recomputation).
// It does NOT verify device signatures on individual records. For full validation callers
// MUST also call Verify on each record in the chain.
func (rv *EvidenceRecordVerifier) VerifyChain(records []map[string]interface{}) *VerificationResult {
	if len(records) == 0 {
		return validResult(nil, "", nil)
	}
	sorted := make([]map[string]interface{}, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		si, _ := sorted[i]["seq"].(float64)
		sj, _ := sorted[j]["seq"].(float64)
		return si < sj
	})

	const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"
	var prevHash string
	var prevSegmentId *int64 // nil = not yet seen
	for _, record := range sorted {
		chainRef, _ := record["chain_ref"].(map[string]interface{})
		seqRaw, _ := record["seq"].(float64)
		hashAlgo, _ := chainRef["hash_algo"].(string)
		if hashAlgo != "sha-256" {
			return rejectResult(fmt.Sprintf(
				"chain_ref.hash_algo must be 'sha-256'; got '%s' at seq=%.0f", hashAlgo, seqRaw,
			))
		}
		storedHash, _ := chainRef["event_hash"].(string)
		storedPrev, _ := chainRef["prev_hash"].(string)

		normEvent, okh := normalizeHex64(storedHash)
		if !okh {
			return rejectResult(fmt.Sprintf(
				"chain_ref.event_hash must be 64 hexadecimal digits at seq=%.0f", seqRaw,
			))
		}
		var normPrevStored string
		var havePrev bool
		if storedPrev != "" {
			var okp bool
			normPrevStored, okp = normalizeHex64(storedPrev)
			if !okp {
				return rejectResult(fmt.Sprintf(
					"chain_ref.prev_hash must be 64 hexadecimal digits at seq=%.0f", seqRaw,
				))
			}
			havePrev = true
		}

		// S2: First record of each segment MUST carry all-zero prev_hash (SPEC.md §chain_ref).
		// Detected when seq==0 (globally first record) or segment_id increments between records.
		var curSegmentId *int64
		if segRaw, ok := chainRef["segment_id"]; ok {
			if segNum, ok2 := segRaw.(float64); ok2 {
				v := int64(segNum)
				curSegmentId = &v
			}
		}
		isSegmentStart := seqRaw == 0
		if curSegmentId != nil && prevSegmentId != nil && *curSegmentId != *prevSegmentId {
			isSegmentStart = true
		}
		if isSegmentStart {
			if havePrev && normPrevStored != zeros64 {
				return rejectResult(fmt.Sprintf(
					"Chain break at seq=%.0f: first record of segment must have all-zero prev_hash", seqRaw,
				))
			}
		}

		// Reconstruct the canonical form used to compute event_hash:
		// record without 'sig', with event_hash zeroed out.
		recordNoSig := make(map[string]interface{}, len(record)-1)
		for k, v := range record {
			if k != "sig" {
				recordNoSig[k] = v
			}
		}
		forHash := deepCopy(recordNoSig).(map[string]interface{})
		cr := forHash["chain_ref"].(map[string]interface{})
		cr["event_hash"] = strings.Repeat("0", 64)
		canonical, _ := canonicalJSON(forHash)
		digest := sha256.Sum256(canonical)
		computedHash := fmt.Sprintf("%x", digest)

		if computedHash != normEvent {
			return rejectResult(fmt.Sprintf(
				"Chain break at seq=%.0f: event_hash mismatch (stored=%s..., computed=%s...)",
				seqRaw, trunc(storedHash, 16), trunc(computedHash, 16),
			))
		}
		if prevHash != "" {
			if !havePrev || normPrevStored != prevHash {
				return rejectResult(fmt.Sprintf(
					"Chain break at seq=%.0f: prev_hash mismatch (stored=%s..., expected=%s...)",
					seqRaw, trunc(storedPrev, 16), trunc(prevHash, 16),
				))
			}
		}
		prevHash = normEvent
		prevSegmentId = curSegmentId
	}
	return validResult(nil, "", nil)
}

// deepCopy returns a deep copy of v via JSON round-trip.
func deepCopy(v interface{}) interface{} {
	b, _ := json.Marshal(v)
	var out interface{}
	json.Unmarshal(b, &out) //nolint:errcheck // input is already valid JSON
	return out
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
