package main

import "context"

// digestSigner signs SHA-256 digests for GitHub JWT verification.
type digestSigner interface {
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
}

// keyImportProvider supplies a wrapping key and imports encrypted key material.
type keyImportProvider interface {
	WrappingPublicKeyDER(ctx context.Context) ([]byte, error)
	ImportKeyMaterial(ctx context.Context, encrypted []byte) (digestSigner, error)
}
