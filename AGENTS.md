# AGENTS.md

CLI that imports GitHub App RSA private keys into AWS KMS. User-facing
usage and prerequisites: see README.md.

## Commands

- Test: `go test -race ./...`
- Format (Go/Nix/YAML): `nix fmt`
- Lint: `go vet ./...` and `staticcheck ./...` (in `nix develop`)
- Vulnerability scan: `govulncheck ./...` (in `nix develop`)
- Check formatting + build (what CI runs): `nix flake check && nix build`

## Code map (flat `package main`)

- `main.go` — Kong CLI definition and flag validation
- `import.go` — `run()` workflow; `encryptKeyMaterial()` (RSA-AES key wrap)
- `pem.go` — PEM (PKCS#1/PKCS#8) → PKCS#8 DER
- `keywrap.go` — RFC 5649 AES Key Wrap with Padding
- `github.go` — KMS-signed JWT validation against GitHub `GET /app`
- Tests: stdlib only; `mock_test.go` (KMS mock), `fake_kms_server_test.go`
  (fake KMS HTTP server via the real AWS SDK)

## Rules

- Conventional Commits in English; the goreleaser changelog filters depend
  on the prefixes.
- Zero buffers holding plaintext key material via `defer` (see `pem.go`,
  `import.go`). Never log or commit key material; `testdata/*.pem` are
  test-only throwaway keys.
- In `run()`, GitHub verification must stay before PEM deletion: a failed
  verification must leave the PEM file on disk (GitHub App keys cannot be
  re-downloaded). `--dry-run` must never call `ImportKeyMaterial`.
