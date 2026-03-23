/*
 * Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
 *
 * YinkoShield Execution Evidence Infrastructure
 * Evidence Token Verifier — CLI entry point
 *
 * Mirrors the Go cmd/verify interface.
 *
 * Build and run:
 *
 *   cd verifiers/java
 *   mvn -q package -DskipTests
 *
 *   # Verify a token from a .jws file
 *   java -jar target/evidence-verifier-1.0.0.jar \
 *       --pubkey ../../keys/demo_public_key.pem \
 *       --token-file ../../examples/demo_sequence/01_minimal_profile.jws \
 *       --skip-freshness
 *
 *   # Verify a token string directly
 *   java -jar target/evidence-verifier-1.0.0.jar \
 *       --pubkey ../../keys/demo_public_key.pem \
 *       --token eyJhbGciOiJFUzI1NiIsImtpZCI6Inlpbmtvc2hpZWxkLmRldmljZS5zaWduLnYxIiwidHlwIjoiSldTIn0...
 *
 *   # Verify a full Evidence Record (JSON)
 *   java -jar target/evidence-verifier-1.0.0.jar \
 *       --pubkey ../../keys/demo_public_key.pem \
 *       --record ../../examples/full_evidence_record.json
 *
 * Exit codes: 0 = VALID, 1 = REJECT or error.
 */
package com.yinkoshield.verifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

/**
 * CLI wrapper for {@link EvidenceTokenVerifier} and {@link EvidenceRecordVerifier}.
 *
 * <p>Flags (accepts {@code --flag value} or {@code -flag value}):
 * <ul>
 *   <li>{@code --pubkey}         Path to PEM public key (required)</li>
 *   <li>{@code --kid}            Key ID (default: {@code yinkoshield.device.sign.v1})</li>
 *   <li>{@code --token}          JWS compact token string</li>
 *   <li>{@code --token-file}     Path to .jws file containing the token</li>
 *   <li>{@code --record}         Path to Evidence Record JSON file</li>
 *   <li>{@code --skip-freshness} Skip freshness window check — use only for static fixtures</li>
 * </ul>
 */
public final class Main {

    private static final String DEFAULT_KID = "yinkoshield.device.sign.v1";

    private Main() {}

    public static void main(String[] args) {
        String  pubkeyPath    = null;
        String  tokenStr      = null;
        String  tokenFile     = null;
        String  recordFile    = null;
        String  kid           = DEFAULT_KID;
        boolean skipFreshness = false;

        // Simple flag parser — supports both -flag and --flag, with space-separated values.
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (normalise(a)) {
                case "skip-freshness":
                    skipFreshness = true;
                    break;
                case "pubkey":
                    pubkeyPath = requireNext(args, i++, "--pubkey");
                    break;
                case "kid":
                    kid = requireNext(args, i++, "--kid");
                    break;
                case "token":
                    tokenStr = requireNext(args, i++, "--token");
                    break;
                case "token-file":
                    tokenFile = requireNext(args, i++, "--token-file");
                    break;
                case "record":
                    recordFile = requireNext(args, i++, "--record");
                    break;
                default:
                    System.err.println("Unknown flag: " + a);
                    printUsage();
                    System.exit(1);
            }
        }

        if (pubkeyPath == null) {
            System.err.println("Error: --pubkey is required");
            printUsage();
            System.exit(1);
        }

        // ── Load public key ──────────────────────────────────────────────────────
        String pemContent;
        try {
            pemContent = readFile(pubkeyPath);
        } catch (IOException e) {
            System.err.println("Failed to read public key: " + e.getMessage());
            System.exit(1);
            return;
        }

        EvidenceTokenVerifier.KeyStore store = new EvidenceTokenVerifier.KeyStore();
        try {
            store.registerPemPublicKey(kid, pemContent);
        } catch (Exception e) {
            System.err.println("Failed to load key: " + e.getMessage());
            System.exit(1);
            return;
        }

        // ── Evidence Record mode ─────────────────────────────────────────────────
        if (recordFile != null) {
            String json;
            try {
                json = readFile(recordFile);
            } catch (IOException e) {
                System.err.println("Failed to read record file: " + e.getMessage());
                System.exit(1);
                return;
            }
            Map<String, Object> record;
            try {
                record = EvidenceTokenVerifier.JsonSimple.parse(json);
            } catch (Exception e) {
                System.err.println("Failed to parse record JSON: " + e.getMessage());
                System.exit(1);
                return;
            }

            EvidenceRecordVerifier rv = new EvidenceRecordVerifier(store);
            EvidenceTokenVerifier.VerificationResult result = rv.verify(record);

            System.out.println();
            System.out.println("Evidence Record: " + (result.isValid() ? "VALID" : "REJECT"));
            if (result.getReason() != null) {
                System.out.println("  Reason:      " + result.getReason());
            }
            if (result.getTrustLevel() != null) {
                System.out.println("  Trust level: " + result.getTrustLevel());
            }
            for (String w : result.getWarnings()) {
                System.out.println("  \u26a0  " + w);
            }
            System.exit(result.isValid() ? 0 : 1);
            return;
        }

        // ── Token mode ───────────────────────────────────────────────────────────
        if (tokenFile != null) {
            try {
                tokenStr = readFile(tokenFile).strip();
            } catch (IOException e) {
                System.err.println("Failed to read token file: " + e.getMessage());
                System.exit(1);
                return;
            }
        }

        if (tokenStr == null || tokenStr.isEmpty()) {
            System.err.println("Provide --token, --token-file, or --record");
            printUsage();
            System.exit(1);
            return;
        }

        EvidenceTokenVerifier verifier = new EvidenceTokenVerifier(store);
        EvidenceTokenVerifier.VerificationResult result = verifier.verify(tokenStr, skipFreshness);

        System.out.println();
        System.out.println("Token: " + (result.isValid() ? "VALID" : "REJECT"));
        if (result.getReason() != null) {
            System.out.println("  Reason:  " + result.getReason());
        }
        if (result.getClaims() != null) {
            Map<String, Object> c = result.getClaims();
            System.out.println("  Event:   " + c.getOrDefault("event_name", ""));
            System.out.println("  Device:  " + c.getOrDefault("did", ""));
            System.out.println("  seq:     " + c.getOrDefault("seq", ""));
            System.out.println("  tctx:    " + c.getOrDefault("tctx", ""));
        }
        if (result.getTrustLevel() != null) {
            System.out.println("  Trust:   " + result.getTrustLevel());
        }
        for (String w : result.getWarnings()) {
            System.out.println("  \u26a0  " + w);
        }
        System.exit(result.isValid() ? 0 : 1);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** Strips leading {@code -} or {@code --} from a flag string. */
    private static String normalise(String flag) {
        if (flag.startsWith("--")) return flag.substring(2);
        if (flag.startsWith("-"))  return flag.substring(1);
        return flag;
    }

    /** Returns {@code args[i + 1]}, or prints an error and exits if out of bounds. */
    private static String requireNext(String[] args, int i, String flagName) {
        if (i + 1 >= args.length) {
            System.err.println("Flag " + flagName + " requires a value");
            System.exit(1);
        }
        return args[i + 1];
    }

    private static String readFile(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }

    private static void printUsage() {
        System.err.println();
        System.err.println("Usage:");
        System.err.println("  java -jar target/evidence-verifier-1.0.0.jar \\");
        System.err.println("      --pubkey <pem-file> \\");
        System.err.println("      [--token <jws-string> | --token-file <path> | --record <path>] \\");
        System.err.println("      [--kid <key-id>] [--skip-freshness]");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  Verify a token file:");
        System.err.println("    java -jar target/evidence-verifier-1.0.0.jar \\");
        System.err.println("        --pubkey ../../keys/demo_public_key.pem \\");
        System.err.println("        --token-file ../../examples/demo_sequence/01_minimal_profile.jws \\");
        System.err.println("        --skip-freshness");
        System.err.println();
        System.err.println("  Verify an Evidence Record:");
        System.err.println("    java -jar target/evidence-verifier-1.0.0.jar \\");
        System.err.println("        --pubkey ../../keys/demo_public_key.pem \\");
        System.err.println("        --record ../../examples/full_evidence_record.json");
    }
}
