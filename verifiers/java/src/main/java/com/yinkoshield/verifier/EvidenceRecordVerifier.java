/*
 * Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
 * SPDX-License-Identifier: Apache-2.0
 *
 * Evidence Record verifier — device-signed ledger records and hash chains.
 * Implements SPEC.md canonical JSON verification and chain_ref linkage (production rules).
 */
package com.yinkoshield.verifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.*;

/**
 * Verifies Evidence Records (ledger JSON) and optional hash-chain integrity.
 * Uses the same {@link EvidenceTokenVerifier.KeyStore} as the token verifier.
 */
public final class EvidenceRecordVerifier {

    private static final Set<String> VALID_TS_SOURCES =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("secure_clock", "ntp", "rtc")));
    private static final long SIGNAL_CLOCK_SKEW_TOLERANCE_MS = 5_000L;

    private final EvidenceTokenVerifier.KeyStore keyStore;

    public EvidenceRecordVerifier(EvidenceTokenVerifier.KeyStore keyStore) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
    }

    /**
     * Verifies the device ES256 signature on a single Evidence Record.
     */
    @SuppressWarnings("unchecked")
    public EvidenceTokenVerifier.VerificationResult verify(Map<String, Object> record) {
        List<String> warnings = new ArrayList<>();

        Object tsSourceRaw = record.get("ts_source");
        if (tsSourceRaw == null) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Record missing required 'ts_source' field");
        }
        String tsSource = String.valueOf(tsSourceRaw);
        if (!VALID_TS_SOURCES.contains(tsSource)) {
            warnings.add("Record ts_source='" + tsSource
                + "' is not a recognised value (ntp, rtc, secure_clock). Treat timestamp with caution.");
        }

        Object recordTsObj = record.get("ts");
        if (recordTsObj instanceof Number) {
            long recordTs = ((Number) recordTsObj).longValue();
            Object signalsRaw = record.get("signals");
            if (signalsRaw instanceof List) {
                for (Object item : (List<?>) signalsRaw) {
                    if (!(item instanceof Map)) continue;
                    Map<String, Object> sigEntry = (Map<String, Object>) item;
                    Object ma = sigEntry.get("measured_at");
                    if (ma instanceof Number
                        && ((Number) ma).longValue() > recordTs + SIGNAL_CLOCK_SKEW_TOLERANCE_MS) {
                        String sigName = String.valueOf(sigEntry.getOrDefault("signal", "?"));
                        return EvidenceTokenVerifier.VerificationResult.rejected(
                            "Record signal '" + sigName + "' has measured_at exceeding record ts + tolerance");
                    }
                }
            }
        }

        Object sigRaw = record.get("sig");
        if (!(sigRaw instanceof Map)) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Record missing 'sig' field");
        }
        Map<String, Object> sigObj = (Map<String, Object>) sigRaw;

        if (!"ES256".equals(sigObj.get("algo"))) {
            return EvidenceTokenVerifier.VerificationResult.rejected(
                "Record sig.algo must be 'ES256'; got '" + sigObj.get("algo") + "'");
        }
        String keyId = (String) sigObj.get("key_id");
        String sigValueB64 = (String) sigObj.get("value");
        if (keyId == null || keyId.isEmpty()) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Record sig missing key_id");
        }
        if (sigValueB64 == null || sigValueB64.isEmpty()) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Record sig missing 'value'");
        }

        PublicKey publicKey = keyStore.lookup(keyId);
        if (publicKey == null) {
            publicKey = keyStore.refetch(keyId);
            if (publicKey == null) {
                return EvidenceTokenVerifier.VerificationResult.rejected("Unknown key_id '" + keyId + "'");
            }
            keyStore.register(keyId, publicKey);
        }

        Map<String, Object> recordNoSig = new LinkedHashMap<>(record);
        recordNoSig.remove("sig");
        final byte[] canonical;
        try {
            canonical = canonicalJsonBytes(deepSortKeys(recordNoSig));
        } catch (Exception e) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Canonical JSON error: " + e.getMessage());
        }

        try {
            byte[] rawSig = EvidenceTokenVerifier.b64urlDecode(sigValueB64);
            if (rawSig.length != 64) {
                return EvidenceTokenVerifier.VerificationResult.rejected(
                    "Record sig: invalid ES256 signature length (" + rawSig.length + " bytes, expected 64)");
            }
            byte[] derSig = EvidenceTokenVerifier.rawEcSigToDer(rawSig);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(canonical);
            if (!sig.verify(derSig)) {
                return EvidenceTokenVerifier.VerificationResult.rejected("Record signature invalid");
            }
        } catch (Exception e) {
            return EvidenceTokenVerifier.VerificationResult.rejected("Record signature error: " + e.getMessage());
        }

        return EvidenceTokenVerifier.VerificationResult.valid(
            null, EvidenceTokenVerifier.evaluateTrust(record), warnings);
    }

    /**
     * Verifies hash-chain linkage across records (sorted by {@code seq}).
     * Does not verify per-record signatures — call {@link #verify(Map)} on each record separately.
     */
    @SuppressWarnings("unchecked")
    public EvidenceTokenVerifier.VerificationResult verifyChain(List<Map<String, Object>> records) {
        if (records == null || records.isEmpty()) {
            return EvidenceTokenVerifier.VerificationResult.valid(null, null, Collections.emptyList());
        }
        List<Map<String, Object>> sorted = new ArrayList<>(records);
        sorted.sort(Comparator.comparingLong(r -> {
            Object s = r.get("seq");
            return s instanceof Number ? ((Number) s).longValue() : 0L;
        }));

        final String ZEROS64 = "0000000000000000000000000000000000000000000000000000000000000000";
        String prevHash = null;
        Long prevSegmentId = null;
        for (Map<String, Object> record : sorted) {
            Object crRaw = record.get("chain_ref");
            if (!(crRaw instanceof Map)) {
                return EvidenceTokenVerifier.VerificationResult.rejected("chain_ref missing or not an object");
            }
            Map<String, Object> chainRef = (Map<String, Object>) crRaw;
            Object seqObj = record.get("seq");
            long seq = seqObj instanceof Number ? ((Number) seqObj).longValue() : 0L;

            if (!"sha-256".equals(chainRef.get("hash_algo"))) {
                return EvidenceTokenVerifier.VerificationResult.rejected(
                    "chain_ref.hash_algo must be 'sha-256'; got '" + chainRef.get("hash_algo") + "' at seq=" + seq);
            }

            String storedHash = (String) chainRef.get("event_hash");
            String storedPrev = (String) chainRef.get("prev_hash");

            String normEvent = normalizeHex64(storedHash);
            if (normEvent == null) {
                return EvidenceTokenVerifier.VerificationResult.rejected(
                    "chain_ref.event_hash must be 64 hexadecimal digits at seq=" + seq);
            }
            String normPrevStored = null;
            boolean havePrev = false;
            if (storedPrev != null && !storedPrev.isEmpty()) {
                normPrevStored = normalizeHex64(storedPrev);
                if (normPrevStored == null) {
                    return EvidenceTokenVerifier.VerificationResult.rejected(
                        "chain_ref.prev_hash must be 64 hexadecimal digits at seq=" + seq);
                }
                havePrev = true;
            }

            // S2: First record of each segment MUST carry all-zero prev_hash (SPEC.md §chain_ref).
            // Detected when seq==0 (globally first record) or segment_id increments between records.
            Long curSegmentId = null;
            Object segRaw = chainRef.get("segment_id");
            if (segRaw instanceof Number) {
                curSegmentId = ((Number) segRaw).longValue();
            }
            boolean isSegmentStart = (seq == 0);
            if (curSegmentId != null && prevSegmentId != null && !curSegmentId.equals(prevSegmentId)) {
                isSegmentStart = true;
            }
            if (isSegmentStart && havePrev && !normPrevStored.equals(ZEROS64)) {
                return EvidenceTokenVerifier.VerificationResult.rejected(
                    "Chain break at seq=" + seq + ": first record of segment must have all-zero prev_hash");
            }

            Map<String, Object> recordNoSig = new LinkedHashMap<>(record);
            recordNoSig.remove("sig");
            Map<String, Object> forHash = deepCopyMap(recordNoSig);
            Map<String, Object> cr = (Map<String, Object>) forHash.get("chain_ref");
            cr.put("event_hash", "0000000000000000000000000000000000000000000000000000000000000000");

            byte[] canonical;
            try {
                canonical = canonicalJsonBytes(deepSortKeys(forHash));
            } catch (Exception e) {
                return EvidenceTokenVerifier.VerificationResult.rejected("Chain canonical JSON error: " + e.getMessage());
            }
            String computed;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                computed = toHex(md.digest(canonical));
            } catch (Exception e) {
                return EvidenceTokenVerifier.VerificationResult.rejected("Chain hash error: " + e.getMessage());
            }

            if (!computed.equals(normEvent)) {
                return EvidenceTokenVerifier.VerificationResult.rejected(
                    "Chain break at seq=" + seq + ": event_hash mismatch");
            }
            if (prevHash != null) {
                if (!havePrev || !normPrevStored.equals(prevHash)) {
                    return EvidenceTokenVerifier.VerificationResult.rejected(
                        "Chain break at seq=" + seq + ": prev_hash mismatch");
                }
            }
            prevHash = normEvent;
            prevSegmentId = curSegmentId;
        }
        return EvidenceTokenVerifier.VerificationResult.valid(null, null, Collections.emptyList());
    }

    // ── Canonical JSON (SPEC.md) ─────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static Object deepSortKeys(Object v) {
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) {
                sorted.put(e.getKey(), deepSortKeys(e.getValue()));
            }
            return sorted;
        }
        if (v instanceof List) {
            List<?> list = (List<?>) v;
            List<Object> out = new ArrayList<>(list.size());
            for (Object o : list) {
                out.add(deepSortKeys(o));
            }
            return out;
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopyMap(Map<String, Object> src) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : src.entrySet()) {
            Object val = e.getValue();
            if (val instanceof Map) {
                out.put(e.getKey(), deepCopyMap((Map<String, Object>) val));
            } else if (val instanceof List) {
                out.put(e.getKey(), deepCopyList((List<?>) val));
            } else {
                out.put(e.getKey(), val);
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> deepCopyList(List<?> src) {
        List<Object> out = new ArrayList<>();
        for (Object o : src) {
            if (o instanceof Map) {
                out.add(deepCopyMap((Map<String, Object>) o));
            } else if (o instanceof List) {
                out.add(deepCopyList((List<?>) o));
            } else {
                out.add(o);
            }
        }
        return out;
    }

    private static byte[] canonicalJsonBytes(Object sorted) {
        StringBuilder sb = new StringBuilder();
        appendJson(sb, sorted);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendJson(StringBuilder sb, Object o) {
        if (o == null) {
            sb.append("null");
            return;
        }
        if (o instanceof Boolean b) {
            sb.append(b);
            return;
        }
        if (o instanceof Number n) {
            if (n instanceof Double d) {
                if (Double.isFinite(d) && d == Math.rint(d)) {
                    sb.append(d.longValue());
                    return;
                }
            }
            if (n instanceof Float f) {
                if (Float.isFinite(f) && f == Math.rint(f)) {
                    sb.append(f.longValue());
                    return;
                }
            }
            sb.append(n.toString());
            return;
        }
        if (o instanceof String s) {
            sb.append('"');
            escapeString(sb, s);
            sb.append('"');
            return;
        }
        if (o instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"');
                escapeString(sb, String.valueOf(e.getKey()));
                sb.append("\":");
                appendJson(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (o instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) o) {
                if (!first) sb.append(',');
                first = false;
                appendJson(sb, x);
            }
            sb.append(']');
        }
    }

    private static void escapeString(StringBuilder sb, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
    }

    private static String normalizeHex64(String s) {
        if (s == null || s.length() != 64) return null;
        char[] out = new char[64];
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') out[i] = c;
            else if (c >= 'a' && c <= 'f') out[i] = c;
            else if (c >= 'A' && c <= 'F') out[i] = (char) (c - 'A' + 'a');
            else return null;
        }
        return new String(out);
    }

    private static String toHex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
