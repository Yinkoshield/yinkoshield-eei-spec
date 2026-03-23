// Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
//
// YinkoShield Execution Evidence Infrastructure
// Evidence Token Verifier — CLI wrapper
//
// Usage:
//
//	go run ./cmd/verify -pubkey ../../keys/demo_public_key.pem \
//	    -token-file ../../examples/demo_sequence/01_minimal_profile.jws -skip-freshness
//	go run ./cmd/verify -pubkey ../../keys/demo_public_key.pem \
//	    -record ../../examples/full_evidence_record.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	verifier "github.com/yinkoshield/yinkoshield-eei-spec/verifiers/go"
)

func main() {
	pubkeyPath := flag.String("pubkey", "", "Path to PEM public key (required)")
	tokenStr   := flag.String("token", "", "JWS compact token string")
	tokenFile  := flag.String("token-file", "", "Path to .jws file")
	recordFile := flag.String("record", "", "Path to Evidence Record JSON")
	kidFlag    := flag.String("kid", "yinkoshield.device.sign.v1", "Key ID")
	skipFresh  := flag.Bool("skip-freshness", false, "Skip freshness check (use for static fixtures)")
	flag.Parse()

	if *pubkeyPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: verify -pubkey <pem> [-token <jws>|-token-file <path>|-record <path>] [-skip-freshness]")
		os.Exit(1)
	}

	store := verifier.NewKeyStore()
	if err := store.LoadPEM(*kidFlag, *pubkeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load key: %v\n", err)
		os.Exit(1)
	}

	if *recordFile != "" {
		data, err := os.ReadFile(*recordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read record: %v\n", err)
			os.Exit(1)
		}
		var record map[string]interface{}
		if err := json.Unmarshal(data, &record); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse record: %v\n", err)
			os.Exit(1)
		}
		rv := verifier.NewEvidenceRecordVerifier(store)
		result := rv.Verify(record)
		fmt.Printf("\nEvidence Record: %s\n", result.Status)
		if result.Reason != "" {
			fmt.Printf("  Reason:      %s\n", result.Reason)
		}
		if result.TrustLevel != "" {
			fmt.Printf("  Trust level: %s\n", result.TrustLevel)
		}
		if !result.OK() {
			os.Exit(1)
		}
		return
	}

	token := *tokenStr
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read token file: %v\n", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Provide -token, -token-file, or -record")
		os.Exit(1)
	}

	v := verifier.NewEvidenceTokenVerifier(store, verifier.DefaultFreshnessWindowMs)
	result := v.Verify(token, *skipFresh)

	fmt.Printf("\nToken: %s\n", result.Status)
	if result.Reason != "" {
		fmt.Printf("  Reason:  %s\n", result.Reason)
	}
	if result.Claims != nil {
		fmt.Printf("  Event:   %s\n", result.Claims.Event)
		fmt.Printf("  Device:  %s\n", result.Claims.Did)
		fmt.Printf("  seq:     %d\n", result.Claims.Seq)
		fmt.Printf("  tctx:    %s\n", result.Claims.Tctx)
	}
	if result.TrustLevel != "" {
		fmt.Printf("  Trust:   %s\n", result.TrustLevel)
	}
	for _, w := range result.Warnings {
		fmt.Printf("  ⚠  %s\n", w)
	}
	if !result.OK() {
		os.Exit(1)
	}
}
