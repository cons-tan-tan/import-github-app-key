# import-github-app-key

A CLI tool that imports GitHub App RSA private keys into AWS KMS or Google Cloud KMS.

Once imported, signing operations (e.g. JWT for GitHub API authentication) are performed within KMS, eliminating the need to store private keys on disk or in application memory.

## Prerequisites

For direct Go usage (`go run ...@latest`):

- Go 1.26.4 or newer

For AWS KMS (the default provider):

- AWS credentials configured (environment variables, `~/.aws/credentials`, etc.)
- A KMS key created in advance with:
  - KeySpec: `RSA_2048`
  - KeyUsage: `SIGN_VERIFY`
  - Origin: `EXTERNAL`

For Google Cloud KMS:

- Google Cloud credentials configured for Application Default Credentials
- A Cloud KMS CryptoKey created for asymmetric signing
- An active ImportJob created with one of these import methods:
  - `RSA_OAEP_3072_SHA256_AES_256`
  - `RSA_OAEP_4096_SHA256_AES_256`

## Quick run

Direct Go usage requires Go 1.26.4 or newer:

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
| `key-id` | AWS KMS key ID/ARN, or GCP CryptoKey resource name |
| `pem-file` | Path to the GitHub App private key PEM file |

### Flags

| Flag | Description |
|------|-------------|
| `-V, --version` | Print version and exit |
| `--provider <aws\|gcp>` | KMS provider (default: `aws`) |
| `-v, --verify <app-id>` | GitHub App ID. Validates the imported key by signing a JWT and calling the GitHub API |
| `-d, --delete` | Delete the PEM file after a successful import without prompting |
| `--dry-run` | Validate the PEM file and KMS wrapping parameters without importing |
| `--github-url <url>` | GitHub API base URL (default: `https://api.github.com`). Set this for GitHub Enterprise Server |
| `--gcp-import-job <name>` | GCP ImportJob resource name. Required when `--provider=gcp` |

### Examples

```sh
# AWS basic import (prompts for PEM deletion after completion)
import-github-app-key arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# AWS verify with GitHub API and auto-delete PEM (for CI/CD)
import-github-app-key -v 12345 -d arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# AWS dry run (validate PEM and KMS wrapping parameters only)
import-github-app-key --dry-run arn:aws:kms:ap-northeast-1:123456789012:key/mrk-xxx ./private-key.pem

# GCP import with an active ImportJob
import-github-app-key \
  --provider gcp \
  --gcp-import-job projects/my-project/locations/global/keyRings/my-ring/importJobs/my-import-job \
  projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  ./private-key.pem

# GCP dry run
import-github-app-key \
  --provider gcp \
  --gcp-import-job projects/my-project/locations/global/keyRings/my-ring/importJobs/my-import-job \
  --dry-run \
  projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  ./private-key.pem

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

# Check formatting
nix flake check

# Build the binary
nix build

# Validate goreleaser config
goreleaser check
```

## How it works

1. Read the PEM file and convert it to PKCS#8 DER format
2. Fetch a wrapping public key from KMS
   - AWS: `GetParametersForImport` with `RSA_AES_KEY_WRAP_SHA_256` and `RSA_4096`
   - GCP: `GetImportJob`; only SHA-256 RSA-OAEP + AES-KWP import methods are supported
3. Encrypt the private key using RSA-AES Key Wrap (SHA-256)
4. Import the encrypted key material into KMS
   - AWS: `ImportKeyMaterial` with `KEY_MATERIAL_DOES_NOT_EXPIRE`
   - GCP: `ImportCryptoKeyVersion` with `RSA_SIGN_PKCS1_2048_SHA256`
5. (with `-v`) Sign a JWT using the imported KMS key version and verify it against the GitHub API (`GET /app`)
6. (with `-d`, or upon interactive confirmation) Delete the PEM file
