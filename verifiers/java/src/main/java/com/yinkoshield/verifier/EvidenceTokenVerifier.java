/*
 * Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
 * SPDX-License-Identifier: Apache-2.0
 *
 * YinkoShield Execution Evidence Infrastructure
 * Evidence Token Verifier — Java Reference Implementation
 *
 * This is a reference implementation of the verification pipeline defined in SPEC.md.
 * It demonstrates sovereign verification: no YinkoShield infrastructure required.
 * Verification uses only the registered device public key.
 *
 * https://github.com/yinkoshield
 */
package com.yinkoshield.verifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Verifies YinkoShield Evidence Tokens (JWS compact) and Evidence Records.
 *
 * <p>Implements the 8-step verification pipeline defined in SPEC.md § Verification:
 * <ol>
 *   <li>Parse JWS structure</li>
 *   <li>Resolve signing key (with key-rotation re-fetch fallback)</li>
 *   <li>Verify ES256 signature (fail closed)</li>
 *   <li>Parse and validate required claims</li>
 *   <li>Enforce freshness window</li>
 *   <li>Deduplicate (replay prevention)</li>
 *   <li>Correlate retries and enforce sequence monotonicity</li>
 *   <li>Evaluate trust level (from linked Evidence Record)</li>
 * </ol>
 *
 * <p>No YinkoShield infrastructure required. Verification uses only the registered
 * device public key obtained during device onboarding.
 *
 * <p>Usage:
 * <pre>{@code
 * KeyStore store = new KeyStore();
 * store.registerPemPublicKey("yinkoshield.device.sign.v1", pemString);
 *
 * EvidenceTokenVerifier verifier = new EvidenceTokenVerifier(store);
 * VerificationResult result = verifier.verify(token, false);
 * if (result.isValid()) {
 *     Map<String, Object> claims = result.getClaims();
 * }
 * }</pre>
 */
public class EvidenceTokenVerifier {

    // ── Constants ──────────────────────────────────────────────────────────────

    /** Current supported schema version. Tokens with higher schema_v are processed with warnings. */
    public static final int SUPPORTED_SCHEMA_VERSION = 1;

    /** Default freshness window: 5 minutes. Operators should configure this to their risk tolerance. */
    public static final long DEFAULT_FRESHNESS_WINDOW_MS = 300_000L;

    /** All required claims for the Minimal Profile. */
    private static final Set<String> REQUIRED_MINIMAL_FIELDS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("eid", "did", "kid", "ts", "seq", "event_name", "tctx", "sig_ref"))
    );

    /** Algorithms accepted for ES256. Reject any other alg value including "none". */
    private static final Set<String> VALID_ALGORITHMS = Collections.singleton("ES256");

    /** Retry event names that trigger sequence-regression checks. */
    private static final Set<String> RETRY_EVENTS = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("payment.retry", "pos.txn.retry", "login.retry", "auth.retry"))
    );

    /** Production limits — SPEC.md "Production implementation requirements". */
    private static final int MAX_JWS_COMPACT_UTF8_BYTES = 24_576;
    private static final int MAX_JWS_HEADER_DECODED_BYTES = 2_048;
    private static final int MAX_JWS_PAYLOAD_DECODED_BYTES = 12_288;
    private static final Set<String> ALLOWED_JWS_HEADER_KEYS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("alg", "kid", "typ")));
    private static final int MAX_HEADER_TYP_LENGTH = 128;
    private static final int MAX_CLAIM_KID_LENGTH = 256;
    private static final int MAX_CLAIM_DID_LENGTH = 128;
    private static final int MAX_CLAIM_TCTX_LENGTH = 256;
    private static final int MAX_CLAIM_EVENT_NAME_LENGTH = 128;
    private static final long MAX_JSON_SAFE_INTEGER = 9_007_199_254_740_991L;
    private static final long MIN_TS_MS_RECOMMENDED = 1_000_000_000_000L;

    private static final Pattern UUID_PATTERN = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    // ── Trust levels ───────────────────────────────────────────────────────────

    /** Trust level reported in VerificationResult. Downstream systems apply policy. */
    public enum TrustLevel {
        HARDWARE_BACKED,    // TEE-attested; strongest trust basis
        HARDWARE_BOUND,     // Hardware keystore; no TEE certificate
        EXECUTION_PROOF,    // Platform state indeterminate
        COMPROMISED_DEVICE, // Integrity failed; evidence recorded for forensics
        SOFTWARE_LAYER      // No platform binding; weakest trust basis
    }

    // ── State ──────────────────────────────────────────────────────────────────

    private final KeyStore keyStore;
    private final long freshnessWindowMs;
    /** Deduplication store: dedup key → expiry unix ms. Entries pruned on access. */
    private final Map<String, Long> dedupStore = new ConcurrentHashMap<>();
    /** Flow store: tctx → ordered list of prior claims. */
    private final Map<String, List<Map<String, Object>>> flowStore = new ConcurrentHashMap<>();
    /** Guards the full read-check-write sequence in Step 7 retry correlation. */
    private final Object flowLock = new Object();

    // ── Constructors ───────────────────────────────────────────────────────────

    /**
     * Creates a verifier with the default freshness window (5 minutes).
     *
     * @param keyStore the key store mapping kid → registered device public key
     */
    public EvidenceTokenVerifier(KeyStore keyStore) {
        this(keyStore, DEFAULT_FRESHNESS_WINDOW_MS);
    }

    /**
     * Creates a verifier with a custom freshness window.
     *
     * @param keyStore           the key store mapping kid → registered device public key
     * @param freshnessWindowMs  maximum acceptable token age in milliseconds
     */
    public EvidenceTokenVerifier(KeyStore keyStore, long freshnessWindowMs) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore must not be null");
        this.freshnessWindowMs = freshnessWindowMs;
    }

    /**
     * Seeds the retry flow store with a prior attempt for {@code tctx}.
     * Package-private for tests in the same package only.
     */
    void seedFlowPrior(String tctx, Map<String, Object> priorClaims) {
        Map<String, Object> copy = new HashMap<>(priorClaims);
        synchronized (flowLock) {
            flowStore.computeIfAbsent(tctx, k -> new ArrayList<>()).add(copy);
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Verifies an Evidence Token (JWS compact string) using the 8-step pipeline.
     *
     * <p>Steps fail closed: any failure returns a REJECT result immediately without
     * evaluating further steps.
     *
     * @param token          the JWS compact token string from the X-YinkoShield-Evidence header
     * @param skipFreshness  when {@code true}, skips freshness enforcement — use only for
     *                       static test fixtures; never in production
     * @return a {@link VerificationResult} whose {@code isValid()} indicates the outcome
     */
    public VerificationResult verify(String token, boolean skipFreshness) {
        List<String> warnings = new ArrayList<>();
        if (token == null) return reject("Token must not be null");
        token = token.trim();
        if (token.getBytes(StandardCharsets.UTF_8).length > MAX_JWS_COMPACT_UTF8_BYTES) {
            return reject("Step 1: JWS compact token exceeds maximum size (" + MAX_JWS_COMPACT_UTF8_BYTES
                + " UTF-8 bytes)");
        }

        // ── Step 1: Parse JWS structure ────────────────────────────────────────
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return reject("Step 1: expected 3 dot-separated JWS segments, got " + parts.length);
        }
        String headerB64  = parts[0];
        String payloadB64 = parts[1];
        String sigB64     = parts[2];

        Map<String, Object> jwsHeader;
        byte[] payloadBytes;
        try {
            byte[] headerBytes = b64urlDecode(headerB64);
            if (headerBytes.length > MAX_JWS_HEADER_DECODED_BYTES) {
                return reject("Step 1: JWS header exceeds maximum decoded size (" + MAX_JWS_HEADER_DECODED_BYTES
                    + " bytes)");
            }
            payloadBytes = b64urlDecode(payloadB64);
            if (payloadBytes.length > MAX_JWS_PAYLOAD_DECODED_BYTES) {
                return reject("Step 1: JWS payload exceeds maximum decoded size (" + MAX_JWS_PAYLOAD_DECODED_BYTES
                    + " bytes)");
            }
            jwsHeader = JsonSimple.parse(headerBytes);
        } catch (Exception e) {
            return reject("Step 1 (parse): " + e.getMessage());
        }

        String hdrProd = validateJwsHeaderAllowlist(jwsHeader);
        if (hdrProd != null) return reject(hdrProd);

        if (!jwsHeader.containsKey("alg")) return reject("Step 1: missing 'alg' in JWS header");
        if (!jwsHeader.containsKey("kid")) return reject("Step 1: missing 'kid' in JWS header");

        String alg = (String) jwsHeader.get("alg");
        String kid = (String) jwsHeader.get("kid");

        if (!VALID_ALGORITHMS.contains(alg)) {
            return reject("Step 1: unsupported algorithm '" + alg + "'. Accepted: " + VALID_ALGORITHMS);
        }

        // ── Step 2: Resolve signing key ────────────────────────────────────────
        // Unknown kid may indicate a key rotation since last onboarding sync.
        // Attempt re-fetch before rejecting — see KeyStore.refetch().
        PublicKey publicKey = keyStore.lookup(kid);
        if (publicKey == null) {
            publicKey = keyStore.refetch(kid);
            if (publicKey == null) {
                return reject("Step 2: unknown kid '" + kid + "'. Device not registered or key rotation not reconciled.");
            }
            keyStore.register(kid, publicKey);
        }

        // ── Step 3: Verify signature (fail closed) ─────────────────────────────
        try {
            byte[] rawSig = b64urlDecode(sigB64);
            if (rawSig.length != 64) {
                return reject("Step 3: invalid ES256 signature length (" + rawSig.length + " bytes, expected 64)");
            }
            byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.UTF_8);
            byte[] derSig = rawEcSigToDer(rawSig);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(signingInput);
            if (!sig.verify(derSig)) {
                return reject("Step 3: invalid signature");
            }
        } catch (Exception e) {
            // Signature.verify throws on invalid input — treat all exceptions as rejection
            if (e.getMessage() != null && e.getMessage().contains("invalid signature")) {
                return reject("Step 3: invalid signature");
            }
            return reject("Step 3 (signature): " + e.getMessage());
        }

        // ── Step 4: Parse and validate claims ──────────────────────────────────
        Map<String, Object> claims;
        try {
            claims = JsonSimple.parse(payloadBytes);
        } catch (Exception e) {
            return reject("Step 4 (parse claims): " + e.getMessage());
        }

        // Normalise legacy 'event' → 'event_name' (SPEC v1.1 backward compat).
        // When both are present, 'event_name' takes precedence.
        if (claims.containsKey("event_name") && claims.containsKey("event")) {
            warnings.add("Step 4: both 'event' and 'event_name' present; 'event_name' takes precedence");
        } else if (!claims.containsKey("event_name") && claims.containsKey("event")) {
            claims.put("event_name", claims.get("event"));
            warnings.add("Step 4: legacy 'event' field normalised to 'event_name'");
        }

        List<String> missing = new ArrayList<>();
        for (String field : REQUIRED_MINIMAL_FIELDS) {
            if (!claims.containsKey(field)) missing.add(field);
        }
        if (!missing.isEmpty()) {
            Collections.sort(missing);
            return reject("Step 4: missing required fields: " + missing);
        }

        String eid = (String) claims.get("eid");
        if (!isValidUuid(eid)) return reject("Step 4: 'eid' is not a valid UUID");

        // kid in JWS header must match kid in payload (SPEC §Verification Step 4)
        String payloadKid = (String) claims.get("kid");
        if (!kid.equals(payloadKid)) {
            return reject("Step 4: kid mismatch — header='" + kid + "' payload='" + payloadKid + "'");
        }

        // tctx must be non-empty, printable, and contain no whitespace or control characters.
        // Reject ASCII controls (< 0x21), DEL (0x7F), and C1 controls (0x80–0x9F).
        String tctx = (String) claims.get("tctx");
        if (tctx == null || tctx.isEmpty()
                || tctx.chars().anyMatch(c -> c < 0x21 || c == 0x7F || (c >= 0x80 && c < 0xA0))) {
            return reject("Step 4: 'tctx' must be a non-empty printable string with no whitespace");
        }

        if (!(claims.get("seq") instanceof Number)) return reject("Step 4: 'seq' must be a number");
        if (!(claims.get("ts")  instanceof Number)) return reject("Step 4: 'ts' must be a number");

        Object sigRefRaw = claims.get("sig_ref");
        if (!(sigRefRaw instanceof Map) || !((Map<?,?>) sigRefRaw).containsKey("ledger_seq")) {
            return reject("Step 4: 'sig_ref' must be an object with 'ledger_seq'");
        }
        // segment_id absent in sig_ref → backward-compat warning (pre-v1.1 tokens)
        if (!((Map<?,?>) sigRefRaw).containsKey("segment_id")) {
            warnings.add("Step 4: sig_ref.segment_id absent (pre-v1.1 token). Processing continues.");
        }

        Object schemaV = claims.get("schema_v");
        if (schemaV instanceof Number && ((Number) schemaV).intValue() != SUPPORTED_SCHEMA_VERSION) {
            warnings.add("Step 4: schema_v=" + schemaV + " > supported=" + SUPPORTED_SCHEMA_VERSION
                + ". Processing known fields only.");
        }

        String bootId = (String) claims.get("boot_id");
        if (bootId != null && !isValidUuid(bootId)) {
            return reject("Step 4: 'boot_id' is not a valid UUID");
        }

        String prod = validateProductionTokenClaims(claims, (Map<String, Object>) sigRefRaw);
        if (prod != null) return reject(prod);

        // ── Step 5: Enforce freshness ──────────────────────────────────────────
        if (!skipFreshness) {
            long nowMs  = Instant.now().toEpochMilli();
            long ts     = ((Number) claims.get("ts")).longValue();
            long ageMs  = Math.abs(nowMs - ts);
            if (ageMs > freshnessWindowMs) {
                return reject("Step 5: token outside freshness window (age=" + ageMs
                    + "ms, window=" + freshnessWindowMs + "ms)");
            }
        }

        // ── Step 6: Deduplicate ────────────────────────────────────────────────
        String did       = (String) claims.get("did");
        String eventName = (String) claims.get("event_name");
        long   seq       = ((Number) claims.get("seq")).longValue();
        long   ts        = ((Number) claims.get("ts")).longValue();

        // Use NUL byte (\0) as separator — tctx is printable and can contain ':', so a colon
        // separator creates a collision class. NUL cannot appear in any valid printable field.
        String dedupKey      = did + "\0" + tctx + "\0" + eventName + "\0" + seq;
        // Expiry: 2 × freshness window from insertion time (SPEC: "MAY be pruned after
        // 2 × freshnessWindowMs has elapsed since insertion"). Must be insertion-based
        // so static test fixtures with historical ts values don't expire immediately.
        long   nowMsDedup    = Instant.now().toEpochMilli();
        long   dedupExpiryMs = nowMsDedup + 2 * freshnessWindowMs;
        // Prune expired entries to bound memory growth, then check for duplicate.
        dedupStore.entrySet().removeIf(e -> e.getValue() <= nowMsDedup);
        if (dedupStore.putIfAbsent(dedupKey, dedupExpiryMs) != null) {
            return reject("Step 6: duplicate token (did=" + did + ", tctx=" + tctx
                + ", event_name=" + eventName + ", seq=" + seq + ")");
        }

        // ── Step 7: Retry correlation ──────────────────────────────────────────
        // Hold flowLock across the full read-check-write to prevent TOCTOU race.
        synchronized (flowLock) {
            if (RETRY_EVENTS.contains(eventName)) {
                List<Map<String, Object>> prior = flowStore.getOrDefault(tctx, Collections.emptyList());
                if (!prior.isEmpty()) {
                    long maxPriorSeq = prior.stream()
                        .mapToLong(c -> ((Number) c.get("seq")).longValue())
                        .max().orElse(0L);
                    if (seq <= maxPriorSeq) {
                        return reject("Step 7: sequence regression in retry. seq=" + seq
                            + " <= prior max=" + maxPriorSeq);
                    }
                    String priorBoot   = (String) prior.get(0).get("boot_id");
                    String currentBoot = (String) claims.get("boot_id");
                    if (priorBoot != null && currentBoot != null && !priorBoot.equals(currentBoot)) {
                        warnings.add("Step 7: boot_id changed mid-flow. "
                            + "May indicate device reboot between retries — review policy.");
                    }
                }
            }
            flowStore.computeIfAbsent(tctx, k -> new ArrayList<>()).add(claims);
        }

        // ── Step 8: Trust level ────────────────────────────────────────────────
        // Full trust evaluation requires the linked Evidence Record.
        // Fetching it is out-of-scope for the inline token verifier; the caller
        // should call evaluateTrust() after retrieving
        // the record via sig_ref.ledger_seq.
        warnings.add("Step 8: ledger record not fetched. Trust level is SOFTWARE_LAYER. "
            + "Fetch the full Evidence Record via sig_ref.ledger_seq for dispute-grade trust.");

        return VerificationResult.valid(claims, TrustLevel.SOFTWARE_LAYER, warnings);
    }

    // ── Static helpers ─────────────────────────────────────────────────────────

    /**
     * Validates token ↔ Evidence Record field equality (SPEC — Production implementation requirements).
     * @return {@code null} if OK, otherwise a rejection reason (signatures not checked here).
     */
    @SuppressWarnings("unchecked")
    public static String verifyTokenRecordBinding(Map<String, Object> claims, Map<String, Object> record) {
        if (!Objects.equals(claims.get("eid"), record.get("eid"))) {
            return "Binding: token eid does not match record eid";
        }
        if (!Objects.equals(claims.get("did"), record.get("device_id"))) {
            return "Binding: token did does not match record device_id";
        }
        if (!Objects.equals(claims.get("tctx"), record.get("tctx"))) {
            return "Binding: token tctx does not match record tctx";
        }
        Number cSeq = (Number) claims.get("seq");
        Number rSeq = (Number) record.get("seq");
        if (cSeq == null || rSeq == null || cSeq.longValue() != rSeq.longValue()) {
            return "Binding: token seq does not match record seq";
        }
        Object sr = claims.get("sig_ref");
        Object cr = record.get("chain_ref");
        if (!(sr instanceof Map) || !(cr instanceof Map)) {
            return "Binding: sig_ref or chain_ref missing or not an object";
        }
        Map<String, Object> sigRef = (Map<String, Object>) sr;
        Map<String, Object> chainRef = (Map<String, Object>) cr;
        Number lsTok = (Number) sigRef.get("ledger_seq");
        Number lsRec = (Number) chainRef.get("ledger_seq");
        if (lsTok == null || lsRec == null || lsTok.longValue() != lsRec.longValue()) {
            return "Binding: sig_ref.ledger_seq does not match chain_ref.ledger_seq";
        }
        if (sigRef.containsKey("segment_id") && chainRef.containsKey("segment_id")) {
            Number a = (Number) sigRef.get("segment_id");
            Number b = (Number) chainRef.get("segment_id");
            if (a == null || b == null || a.longValue() != b.longValue()) {
                return "Binding: sig_ref.segment_id does not match chain_ref.segment_id";
            }
        }
        return null;
    }

    /**
     * Evaluates trust level from a fetched Evidence Record.
     * Call this after retrieving the record via {@code sig_ref.ledger_seq}.
     *
     * @param record the deserialized Evidence Record
     * @return the trust level to be used for policy decisions
     */
    @SuppressWarnings("unchecked")
    public static TrustLevel evaluateTrust(Map<String, Object> record) {
        Object attRaw = record.get("attestation_ref");
        if (!(attRaw instanceof Map)) return TrustLevel.SOFTWARE_LAYER;
        Map<String, Object> att = (Map<String, Object>) attRaw;
        String state = (String) att.get("device_state");
        if ("verified".equals(state))          return TrustLevel.HARDWARE_BACKED;
        if ("hardware_keystore".equals(state)) return TrustLevel.HARDWARE_BOUND;
        if ("unknown".equals(state))           return TrustLevel.EXECUTION_PROOF;
        if ("failed".equals(state))            return TrustLevel.COMPROMISED_DEVICE;
        return TrustLevel.SOFTWARE_LAYER;
    }

    /** Decodes a Base64URL-encoded string to bytes (handles missing padding). */
    static byte[] b64urlDecode(String s) {
        s = s.replace('-', '+').replace('_', '/');
        switch (s.length() % 4) {
            case 2: s += "=="; break;
            case 3: s += "=";  break;
            default: break;
        }
        return Base64.getDecoder().decode(s);
    }

    /**
     * Converts a raw 64-byte R||S EC signature to DER format expected by Java's
     * {@link Signature} API. The raw format is used in JWS (RFC 7518 § 3.4).
     */
    static byte[] rawEcSigToDer(byte[] raw) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
        byte[] rb = toUnsignedByteArray(r);
        byte[] sb = toUnsignedByteArray(s);
        int seqLen = 2 + rb.length + 2 + sb.length;
        byte[] der = new byte[2 + seqLen];
        int i = 0;
        der[i++] = 0x30;
        der[i++] = (byte) seqLen;
        der[i++] = 0x02;
        der[i++] = (byte) rb.length;
        System.arraycopy(rb, 0, der, i, rb.length); i += rb.length;
        der[i++] = 0x02;
        der[i++] = (byte) sb.length;
        System.arraycopy(sb, 0, der, i, sb.length);
        return der;
    }

    /** Returns DER INTEGER bytes: unsigned big-endian, with leading 0x00 if high bit is set. */
    private static byte[] toUnsignedByteArray(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length > 1 && b[0] == 0x00) {
            b = Arrays.copyOfRange(b, 1, b.length);
        }
        if (b.length == 0) {
            return new byte[]{0x00}; // BigInteger.ZERO — encode as single zero byte
        }
        if ((b[0] & 0x80) != 0) {
            byte[] padded = new byte[b.length + 1];
            padded[0] = 0x00;
            System.arraycopy(b, 0, padded, 1, b.length);
            return padded;
        }
        return b;
    }

    private static boolean isValidUuid(String s) {
        return s != null && UUID_PATTERN.matcher(s).matches();
    }

    private static String validateJwsHeaderAllowlist(Map<String, Object> h) {
        for (String k : h.keySet()) {
            if (!ALLOWED_JWS_HEADER_KEYS.contains(k)) {
                return "Step 1: disallowed JWS header key(s) — '" + k + "' is not permitted";
            }
        }
        if (!(h.get("alg") instanceof String) || !(h.get("kid") instanceof String)) {
            return "Step 1: JWS header 'alg' and 'kid' must be strings";
        }
        if (h.containsKey("typ")) {
            Object typ = h.get("typ");
            if (!(typ instanceof String)) {
                return "Step 1: JWS header 'typ' must be a string";
            }
            if (((String) typ).length() > MAX_HEADER_TYP_LENGTH) {
                return "Step 1: JWS header 'typ' exceeds max length " + MAX_HEADER_TYP_LENGTH;
            }
        }
        return null;
    }

    private static boolean isWholeNumber(Number n) {
        if (n instanceof Double d) {
            return !d.isNaN() && !d.isInfinite() && d == Math.rint(d);
        }
        if (n instanceof Float f) {
            return !f.isNaN() && !f.isInfinite() && f == Math.rint(f);
        }
        return true;
    }

    private static String checkInt53NonNeg(String name, Number n) {
        if (n == null || !isWholeNumber(n)) {
            return "Step 4: '" + name + "' must be an integer";
        }
        long v = n.longValue();
        if (v < 0 || v > MAX_JSON_SAFE_INTEGER) {
            return "Step 4: '" + name + "' out of allowed range [0, " + MAX_JSON_SAFE_INTEGER + "]";
        }
        return null;
    }

    private static String validateProductionTokenClaims(Map<String, Object> claims, Map<String, Object> sigRef) {
        String kid = (String) claims.get("kid");
        if (kid != null && kid.length() > MAX_CLAIM_KID_LENGTH) {
            return "Step 4: 'kid' exceeds max length " + MAX_CLAIM_KID_LENGTH;
        }
        String did = (String) claims.get("did");
        if (did != null && did.length() > MAX_CLAIM_DID_LENGTH) {
            return "Step 4: 'did' exceeds max length " + MAX_CLAIM_DID_LENGTH;
        }
        String tctx = (String) claims.get("tctx");
        if (tctx != null && tctx.length() > MAX_CLAIM_TCTX_LENGTH) {
            return "Step 4: 'tctx' exceeds max length " + MAX_CLAIM_TCTX_LENGTH;
        }
        String en = (String) claims.get("event_name");
        if (en != null && en.length() > MAX_CLAIM_EVENT_NAME_LENGTH) {
            return "Step 4: 'event_name' exceeds max length " + MAX_CLAIM_EVENT_NAME_LENGTH;
        }
        Number ts = (Number) claims.get("ts");
        Number seq = (Number) claims.get("seq");
        String err = checkInt53NonNeg("ts", ts);
        if (err != null) return err;
        err = checkInt53NonNeg("seq", seq);
        if (err != null) return err;
        if (ts.longValue() < MIN_TS_MS_RECOMMENDED) {
            return "Step 4: 'ts' is below minimum allowed (" + MIN_TS_MS_RECOMMENDED + " ms epoch)";
        }
        err = checkInt53NonNeg("sig_ref.ledger_seq", (Number) sigRef.get("ledger_seq"));
        if (err != null) return err;
        if (sigRef.containsKey("segment_id")) {
            err = checkInt53NonNeg("sig_ref.segment_id", (Number) sigRef.get("segment_id"));
            if (err != null) return err;
        }
        return null;
    }

    private static VerificationResult reject(String reason) {
        return VerificationResult.rejected(reason);
    }

    // ── Inner classes ──────────────────────────────────────────────────────────

    /**
     * Verification result returned by all verify methods.
     * Callers should check {@link #isValid()} before accessing {@link #getClaims()}.
     */
    public static class VerificationResult {
        private final boolean valid;
        private final String reason;
        private final Map<String, Object> claims;
        private final TrustLevel trustLevel;
        private final List<String> warnings;

        private VerificationResult(boolean valid, String reason, Map<String, Object> claims,
                                   TrustLevel trustLevel, List<String> warnings) {
            this.valid      = valid;
            this.reason     = reason;
            this.claims     = claims;
            this.trustLevel = trustLevel;
            this.warnings   = warnings != null ? Collections.unmodifiableList(warnings) : Collections.emptyList();
        }

        public static VerificationResult rejected(String reason) {
            return new VerificationResult(false, reason, null, null, null);
        }

        public static VerificationResult valid(Map<String, Object> claims, TrustLevel trust, List<String> warnings) {
            return new VerificationResult(true, null, claims, trust, warnings);
        }

        /** Returns {@code true} if the token passed all verification steps. */
        public boolean isValid()             { return valid; }
        /** Returns the rejection reason, or {@code null} if valid. */
        public String getReason()            { return reason; }
        /** Returns parsed claims, or {@code null} if rejected. */
        public Map<String, Object> getClaims() { return claims; }
        /** Returns the trust level assigned to this token. */
        public TrustLevel getTrustLevel()    { return trustLevel; }
        /** Returns non-fatal warnings accumulated during verification. */
        public List<String> getWarnings()    { return warnings; }

        @Override
        public String toString() {
            return valid
                ? "VerificationResult{VALID, trust=" + trustLevel + ", warnings=" + warnings.size() + "}"
                : "VerificationResult{REJECT, reason='" + reason + "'}";
        }
    }

    /**
     * Maps kid (key identifier) → device public key.
     *
     * <p>In production, back this with your device onboarding database.
     * Override {@link #refetch(String)} to query a live key registry.
     */
    public static class KeyStore {
        private final Map<String, PublicKey> store = new ConcurrentHashMap<>();

        /** Registers a public key for the given kid. */
        public void register(String kid, PublicKey key) {
            store.put(kid, Objects.requireNonNull(key));
        }

        /**
         * Registers a public key from a PEM-encoded string.
         * Supports X.509 SubjectPublicKeyInfo format (standard PEM public key).
         *
         * @param kid    the key identifier
         * @param pemKey the PEM-encoded public key string
         * @throws Exception if the key cannot be parsed
         */
        public void registerPemPublicKey(String kid, String pemKey) throws Exception {
            String stripped = pemKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(stripped);
            KeyFactory kf = KeyFactory.getInstance("EC");
            java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
            PublicKey key = kf.generatePublic(spec);
            store.put(kid, key);
        }

        /** Returns the registered public key for the given kid, or {@code null} if not found. */
        public PublicKey lookup(String kid) {
            return store.get(kid);
        }

        /**
         * Attempts to re-fetch an unknown key (e.g. after key rotation).
         * Override this in production to query your onboarding service.
         * Returns {@code null} if the kid is genuinely unregistered.
         *
         * @param kid the key identifier to fetch
         * @return the public key, or {@code null}
         */
        public PublicKey refetch(String kid) {
            return null;
        }
    }

    /**
     * Minimal JSON parser for the subset of JSON used in Evidence Tokens and Records.
     * Parses flat and nested objects, arrays, strings, numbers, and booleans.
     * Not a full JSON parser — use a proper library (Jackson, Gson) in production.
     */
    static class JsonSimple {
        private static final int MAX_DEPTH = 32;

        /** Parses a JSON object from a UTF-8 byte array. */
        static Map<String, Object> parse(byte[] bytes) throws Exception {
            return parse(new String(bytes, StandardCharsets.UTF_8));
        }

        /** Parses a JSON object from a String. */
        @SuppressWarnings("unchecked")
        static Map<String, Object> parse(String json) throws Exception {
            json = json.trim();
            if (!json.startsWith("{")) throw new IllegalArgumentException("Expected JSON object");
            Object result = parseValue(json, new int[]{0}, 0);
            return (Map<String, Object>) result;
        }

        private static Object parseValue(String s, int[] pos, int depth) throws Exception {
            if (depth > MAX_DEPTH) throw new Exception("JSON nesting depth exceeds maximum (" + MAX_DEPTH + ")");
            skipWhitespace(s, pos);
            if (pos[0] >= s.length()) throw new Exception("Unexpected end of input");
            char c = s.charAt(pos[0]);
            if (c == '{')     return parseObject(s, pos, depth + 1);
            if (c == '[')     return parseArray(s, pos, depth + 1);
            if (c == '"')     return parseString(s, pos);
            if (c == 't' || c == 'f') return parseBoolean(s, pos);
            if (c == 'n')     { pos[0] += 4; return null; }
            return parseNumber(s, pos);
        }

        private static Map<String, Object> parseObject(String s, int[] pos, int depth) throws Exception {
            Map<String, Object> map = new LinkedHashMap<>();
            pos[0]++; // skip '{'
            skipWhitespace(s, pos);
            if (pos[0] < s.length() && s.charAt(pos[0]) == '}') { pos[0]++; return map; }
            while (pos[0] < s.length()) {
                skipWhitespace(s, pos);
                String key = parseString(s, pos);
                skipWhitespace(s, pos);
                if (s.charAt(pos[0]) != ':') throw new Exception("Expected ':'");
                pos[0]++;
                Object value = parseValue(s, pos, depth);
                // Reject duplicate keys — silently overwriting them would allow an attacker
                // to smuggle a second value for security-critical fields like "alg".
                if (map.containsKey(key)) {
                    throw new Exception("Duplicate key '" + key + "' in JSON object");
                }
                map.put(key, value);
                skipWhitespace(s, pos);
                if (pos[0] >= s.length()) break;
                char next = s.charAt(pos[0]);
                if (next == '}') { pos[0]++; return map; }
                if (next == ',') { pos[0]++; } else throw new Exception("Expected ',' or '}'");
            }
            return map;
        }

        private static List<Object> parseArray(String s, int[] pos, int depth) throws Exception {
            List<Object> list = new ArrayList<>();
            pos[0]++; // skip '['
            skipWhitespace(s, pos);
            if (pos[0] < s.length() && s.charAt(pos[0]) == ']') { pos[0]++; return list; }
            while (pos[0] < s.length()) {
                list.add(parseValue(s, pos, depth));
                skipWhitespace(s, pos);
                if (pos[0] >= s.length()) break;
                char next = s.charAt(pos[0]);
                if (next == ']') { pos[0]++; return list; }
                if (next == ',') { pos[0]++; } else throw new Exception("Expected ',' or ']'");
            }
            return list;
        }

        private static String parseString(String s, int[] pos) throws Exception {
            if (s.charAt(pos[0]) != '"') throw new Exception("Expected '\"'");
            pos[0]++;
            StringBuilder sb = new StringBuilder();
            while (pos[0] < s.length()) {
                char c = s.charAt(pos[0]++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos[0] >= s.length()) throw new Exception("Truncated escape sequence");
                    char esc = s.charAt(pos[0]++);
                    switch (esc) {
                        case '"':  sb.append('"');  break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/');  break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'u':
                            if (pos[0] + 4 > s.length()) throw new Exception("Incomplete \\u escape");
                            int cp = Integer.parseInt(s.substring(pos[0], pos[0] + 4), 16);
                            pos[0] += 4;
                            sb.appendCodePoint(cp);
                            break;
                        default: sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new Exception("Unterminated string");
        }

        private static Number parseNumber(String s, int[] pos) {
            int start = pos[0];
            while (pos[0] < s.length()) {
                char c = s.charAt(pos[0]);
                if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n' || c == '\r' || c == '\t') break;
                pos[0]++;
            }
            String num = s.substring(start, pos[0]);
            if (num.contains(".") || num.contains("e") || num.contains("E")) {
                return Double.parseDouble(num);
            }
            return Long.parseLong(num);
        }

        private static boolean parseBoolean(String s, int[] pos) {
            if (s.startsWith("true", pos[0]))  { pos[0] += 4; return true; }
            if (s.startsWith("false", pos[0])) { pos[0] += 5; return false; }
            throw new IllegalArgumentException("Invalid boolean at position " + pos[0]);
        }

        private static void skipWhitespace(String s, int[] pos) {
            while (pos[0] < s.length() && Character.isWhitespace(s.charAt(pos[0]))) pos[0]++;
        }
    }
}
