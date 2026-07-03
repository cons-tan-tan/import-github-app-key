package main

import "context"

// digestSigner signs SHA-256 digests for GitHub JWT verification.
type digestSigner interface {
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

// keyImportProvider supplies a wrapping key and imports encrypted key material.
// ImportKeyMaterial returns a signer for the imported key and a human-readable
// identifier of the import destination (AWS: key ID, GCP: CryptoKeyVersion
// resource name).
type keyImportProvider interface {
	WrappingPublicKeyDER(ctx context.Context) ([]byte, error)
	ImportKeyMaterial(ctx context.Context, encrypted []byte) (digestSigner, string, error)
}
