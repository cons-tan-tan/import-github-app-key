# AGENTS.md

For changes to user-facing behavior, consult [README.md](README.md) for setup,
usage, and security limits.

## Checks

Run from the repository root in `nix develop`, or use the toolchain in
[rust-toolchain.toml](rust-toolchain.toml). Choose checks relevant to the change;
the full CI definitions are in [check.yaml](.github/workflows/check.yaml).

Use the throwaway keys in `testdata/` and local fake services for tests.
These tests do not access production. Run relevant local checks and fix regressions
from the requested change without asking for confirmation at each step.

- Rust: `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`.
- Format Rust/Nix/YAML: `nix fmt` (Rust only: `cargo fmt --all`).
- Nix: `nix flake check && nix build`.
- AWS KMS integration: `nix build .#kms-integration-tests`. Run when changing
  AWS import/signing, key wrapping, or workflow behavior. This separate crate
  also runs in its own CI job and requires several GiB of build memory.
  After changing the root package version or dependencies, refresh the integration
  lockfile with `cargo update --manifest-path integration-tests/kms/Cargo.toml --package import-github-app-key`.
- Dependencies: `cargo audit`; exceptions and their rationale live in
  [.cargo/audit.toml](.cargo/audit.toml).
- Actions: regenerate `.github/workflows/actions.lock` with `gh-actions-lock`
  after changing `uses:` references; commit the generated file without hand edits.

## Change rules

- Use Conventional Commits in English.
- Keep application-owned plaintext key buffers in `SecretBox` or `Zeroizing`
  from allocation through destruction, including error paths. Avoid reallocations.
- Keep PEM parsing and encryption in a synchronous scope that ends before network
  requests or prompts. Never log or commit real key material.
- Keep the AES dependency's `zeroize` feature enabled and RSA private components
  in types that zeroize on drop. Production signing and decryption belong in KMS;
  do not add local private-key signing or decryption.
- Verify before deleting the PEM when verification is requested, and recheck its
  contents before deletion. Failed import or verification must preserve the PEM.
  `--dry-run` must never import key material or delete a PEM.
- Update affected documentation with behavior changes. Keep usage and limitations
  in README, agent instructions here, and implementation rationale beside the code.
  Link to `--help` or configuration instead of copying option lists, tool versions,
  or workflow steps into prose.
