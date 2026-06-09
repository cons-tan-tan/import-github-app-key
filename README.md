# import-github-app-key

A CLI tool that imports GitHub App RSA private keys into AWS KMS.

Once imported, signing operations (e.g. JWT for GitHub API authentication) are performed within KMS, eliminating the need to store private keys on disk or in application memory.

## Prerequisites

- AWS credentials configured (environment variables, `~/.aws/credentials`, etc.)
- A KMS key created in advance with:
  - KeySpec: `RSA_2048`
  - KeyUsage: `SIGN_VERIFY`
  - Origin: `EXTERNAL`

## Quick run

```sh
go run github.com/cons-tan-tan/import-github-app-key@latest --help
```

Nix flakes are also supported:

```sh
nix run github:cons-tan-tan/import-github-app-key -- --help
```

## Usage

With Go:

```sh
go run github.com/cons-tan-tan/import-github-app-key@latest [flags] <key-id> <pem-file>
```

With Nix:

```sh
nix run github:cons-tan-tan/import-github-app-key -- [flags] <key-id> <pem-file>
```

The examples below use `import-github-app-key` as the command name shown in help output. For one-shot use, replace it with either runner above.

```
import-github-app-key [flags] <key-id> <pem-file>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `key-id` | KMS key ID or ARN |
| `pem-file` | Path to the GitHub App private key PEM file |

### Flags

| Flag | Description |
|------|-------------|
| `-V, --version` | Print version and exit |
| `-v, --verify <app-id>` | GitHub App ID. Validates the imported key by signing a JWT and calling the GitHub API |
| `-d, --delete` | Delete the PEM file after a successful import without prompting |
| `--dry-run` | Validate the PEM file and KMS wrapping parameters without importing |
| `--github-url <url>` | GitHub API base URL (default: `https://api.github.com`). Set this for GitHub Enterprise Server |

### Examples

```sh
# Basic import (prompts for PEM deletion after completion)
import-github-app-key arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# Verify with GitHub API and auto-delete PEM (for CI/CD)
import-github-app-key -v 12345 -d arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# Dry run (validate PEM and KMS wrapping parameters only)
import-github-app-key --dry-run arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# GitHub Enterprise Server
import-github-app-key -v 12345 --github-url https://github.example.com/api/v3 arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem
```

## Development

```sh
# Enter the dev shell
nix develop

# Run tests
go test -race ./...

# Format all files (Go, Nix, YAML)
nix fmt

# Check formatting + Nix build
nix flake check

# Build the binary
nix build

# Validate goreleaser config
goreleaser check
```

## How it works

1. Read the PEM file and convert it to PKCS#8 DER format
2. Fetch a wrapping public key from KMS
3. Encrypt the private key using RSA-AES Key Wrap (SHA-256)
4. Import the encrypted key material into KMS
5. (with `-v`) Sign a JWT using the KMS key and verify it against the GitHub API (`GET /app`)
6. (with `-d`, or upon interactive confirmation) Delete the PEM file
