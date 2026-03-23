# YinkoShield Evidence Token Verifier — Go

A Go reference implementation of the Evidence Token verification pipeline specified in SPEC.md.
Built with only the Go standard library — no external dependencies. Part of the yinkoshield-eei-spec repository.

## Requirements

Go 1.21 or later.

## Import

```go
import verifier "github.com/yinkoshield/yinkoshield-eei-spec/verifiers/go"
```

## Programmatic usage

```go
package main

import (
    "log"
    verifier "github.com/yinkoshield/yinkoshield-eei-spec/verifiers/go"
)

func main() {
    store := verifier.NewKeyStore()
    if err := store.LoadPEM("yinkoshield.device.sign.v1", "path/to/public_key.pem"); err != nil {
        log.Fatal(err)
    }

    v := verifier.NewEvidenceTokenVerifier(store, verifier.DefaultFreshnessWindowMs)
    result := v.Verify(tokenString, false)

    if result.OK() {
        log.Printf("✓ Token valid: event=%s trust=%s", result.Claims.Event, result.TrustLevel)
    } else {
        log.Printf("✗ Rejected: %s", result.Reason)
    }
}
```

## CLI

```bash
go run ./cmd/verify \
  -pubkey ../../keys/demo_public_key.pem \
  -token-file ../../examples/demo_sequence/01_minimal_profile.jws \
  -skip-freshness

go run ./cmd/verify \
  -pubkey ../../keys/demo_public_key.pem \
  -record ../../examples/full_evidence_record.json
```

## Testing

```bash
go test ./... -v
```

Runs all 34 tests: valid token verification, signature forgery, algorithm confusion,
freshness enforcement, replay detection, retry correlation, chain integrity, and trust levels.

## License

Copyright (c) 2025-2026 Yinkozi Group — YinkoShield
