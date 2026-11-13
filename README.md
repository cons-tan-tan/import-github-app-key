# import-github-app-key

Import GitHub App private keys into [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html)
or [Google Cloud KMS](https://docs.cloud.google.com/kms/docs/key-import) so your
application can sign JWTs through KMS without reading the private key.

## Why this tool?

GitHub [suggests storing App private keys in a key vault and making them sign-only](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps#storing-private-keys).
With this approach, your application requests signatures from KMS while the
private key stays in KMS.

Importing GitHub's downloaded PEM requires format conversion and key wrapping
to protect it in transit. `import-github-app-key` handles that work for you:

- **One import command.** Takes the PEM directly and handles conversion,
  wrapping, and import for either provider, without custom shell scripts or
  separate OpenSSL commands.
- **Careful key handling.** Converts and wraps the key in memory without
  creating plaintext intermediate files. Plaintext buffers owned by the tool
  are cleared when released, including on errors, before upload or prompts.
- **Verify before cleanup.** With `--verify`, confirms that the imported key
  can authenticate as your GitHub App by signing a JWT in KMS and calling the
  GitHub API. Requested verification must succeed before PEM deletion.

After [setting up credentials and the destination KMS resources](#prerequisites),
import and verify an AWS key with:

```sh
import-github-app-key --verify 12345 \
  arn:aws:kms:ap-northeast-1:123456789012:key/your-key-id ./private-key.pem
```

See [Usage](#usage) for Google Cloud KMS. Configure your application's JWT signing
to use the imported key through KMS. See [Key handling and deletion](#key-handling-and-deletion)
for the limits of memory clearing and file deletion.

## Install and run

From a checkout, use the Rust toolchain in [rust-toolchain.toml](rust-toolchain.toml)
and a C/C++ compiler for the SDKs' TLS implementation (Clang/LLVM on Windows ARM64):

```sh
cargo install --locked --path .
import-github-app-key --help
```

On Linux or Apple Silicon macOS, Nix can run it without installation:

```sh
nix run github:cons-tan-tan/import-github-app-key -- --help
```

Release builds target Linux, macOS, and Windows on x86-64 and ARM64, with SHA-256
checksums. Linux binaries require glibc 2.35 or newer; Mac binaries target macOS 11
or newer. Published versions appear on
[GitHub Releases](https://github.com/cons-tan-tan/import-github-app-key/releases).
Release assets and tags are immutable after publication; use
[`gh release verify-asset`](https://cli.github.com/manual/gh_release_verify-asset)
to verify downloaded files.

## Prerequisites

The input must be an unencrypted RSA-2048 private key in PKCS#1 or PKCS#8 PEM format.

For [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html) (the default provider):

- Configure AWS credentials and a region through your AWS profile or environment
  variables (such as `AWS_REGION`).
- Create a KMS key with `KeySpec: RSA_2048`, `KeyUsage: SIGN_VERIFY`, and
  `Origin: EXTERNAL`.

For [Google Cloud KMS](https://docs.cloud.google.com/kms/docs/importing-a-key):

- Configure Application Default Credentials.
- Create a CryptoKey for asymmetric signing and an active ImportJob using
  `RSA_OAEP_3072_SHA256_AES_256` or `RSA_OAEP_4096_SHA256_AES_256`.

## Usage

```text
import-github-app-key [OPTIONS] <KEY_ID> <PEM_FILE>
```

For AWS, pass the KMS key ID or ARN. Use `--verify` with your GitHub App ID to
check the imported key by signing a JWT in KMS and calling the GitHub API:

```sh
import-github-app-key --verify 12345 \
  arn:aws:kms:ap-northeast-1:123456789012:key/your-key-id ./private-key.pem
```

For GCP, pass the CryptoKey resource name and its ImportJob:

```sh
import-github-app-key --provider gcp --verify 12345 \
  --gcp-import-job projects/my-project/locations/global/keyRings/my-ring/importJobs/my-import-job \
  projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  ./private-key.pem
```

For GitHub Enterprise Server, add `--github-url https://github.example.com/api/v3`.
Verification requires an HTTPS URL without embedded credentials, a query, or a fragment.

Use `--dry-run` to validate the PEM and wrapping parameters without importing or
deleting anything. It still contacts KMS and requires credentials; it cannot be
combined with `--verify` or `--delete`. Run `--help` for the full option reference.

## Key handling and deletion

After a successful import, the CLI prompts before deleting the PEM. `--delete`
skips the prompt. If `--verify` is supplied, verification must also succeed before
deletion. Failed import or verification leaves the PEM in place, and deletion is
refused if its contents have changed since encryption.

Application-owned plaintext buffers are cleared on drop, including error paths,
and released before network requests or prompts. Complete memory erasure is not
guaranteed: dependencies can leave internal temporary allocations, and compiler
copies, CPU registers, swap, hibernation images, and core dumps are not covered.

File deletion is not secure erasure of storage. The content check and deletion
are not atomic; keep the PEM in a directory that other processes cannot modify
while the import is running.

## Development

Use `nix develop` for the development tools. Check commands and contribution rules
are in [AGENTS.md](AGENTS.md); the executable CI definitions are in
[check.yaml](.github/workflows/check.yaml).

The optional [AWS KMS integration suite](integration-tests/kms) uses an in-memory
AWS emulator and the throwaway keys in `testdata/`, without cloud credentials.
Its dependencies are isolated from the normal build and tests. Use the dedicated
Nix target listed in [AGENTS.md](AGENTS.md); the first build needs several GiB of
memory. The suite checks key import, signing, dry-run, and PEM preservation, but
does not establish compatibility with every behavior of the live AWS service.

Release packaging is configured in [dist-workspace.toml](dist-workspace.toml).
The [build workflow](.github/workflows/dist.yaml) contains the reproduction commands;
the [release workflow](.github/workflows/release.yaml) publishes tags matching
the package version in [Cargo.toml](Cargo.toml).
