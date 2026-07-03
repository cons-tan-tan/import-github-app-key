package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// GCPKMSClient is the subset of Cloud KMS client methods used by this tool.
type GCPKMSClient interface {
	GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...gax.CallOption) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

type gcpProvider struct {
	client        GCPKMSClient
	cryptoKeyName string
	importJobName string
	pollInterval  time.Duration
	pollMaxWait   time.Duration
}

func newGCPProvider(client GCPKMSClient, cryptoKeyName, importJobName string) *gcpProvider {
	return &gcpProvider{
		client:        client,
		cryptoKeyName: cryptoKeyName,
		importJobName: importJobName,
		pollInterval:  2 * time.Second,
		pollMaxWait:   5 * time.Minute,
	}
}

func (p *gcpProvider) WrappingPublicKeyDER(ctx context.Context) ([]byte, error) {
	job, err := p.client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: p.importJobName})
	if err != nil {
		return nil, fmt.Errorf("failed to get GCP import job: %w", err)
	}
	if job.GetState() != kmspb.ImportJob_ACTIVE {
		return nil, fmt.Errorf("GCP import job is not active: %s", job.GetState())
	}
	switch job.GetImportMethod() {
	case kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256, kmspb.ImportJob_RSA_OAEP_4096_SHA256_AES_256:
	default:
		return nil, fmt.Errorf("unsupported GCP import method %s: supported methods are RSA_OAEP_3072_SHA256_AES_256 and RSA_OAEP_4096_SHA256_AES_256", job.GetImportMethod())
	}

	publicKeyPEM := job.GetPublicKey().GetPem()
	if publicKeyPEM == "" {
		return nil, fmt.Errorf("GCP import job returned an empty wrapping public key")
	}
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode GCP import job wrapping public key PEM")
	}
	return block.Bytes, nil
}

func (p *gcpProvider) ImportKeyMaterial(ctx context.Context, encrypted []byte) (digestSigner, string, error) {
	version, err := p.client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     p.cryptoKeyName,
		Algorithm:  kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		ImportJob:  p.importJobName,
		WrappedKey: encrypted,
	})
	if err != nil {
		return nil, "", err
	}
	if version.GetName() == "" {
		return nil, "", fmt.Errorf("GCP import returned an empty CryptoKeyVersion name")
	}
	version, err = p.waitForEnabled(ctx, version)
	if err != nil {
		return nil, "", err
	}
	keyVersionName := version.GetName()
	return &gcpSigner{client: p.client, keyVersionName: keyVersionName}, keyVersionName, nil
}

// waitForEnabled polls the imported CryptoKeyVersion until Cloud KMS marks it
// ENABLED. ImportCryptoKeyVersion is asynchronous: the version starts in
// PENDING_IMPORT and cannot sign until the import completes.
func (p *gcpProvider) waitForEnabled(ctx context.Context, version *kmspb.CryptoKeyVersion) (*kmspb.CryptoKeyVersion, error) {
	var waited time.Duration
	for {
		switch version.GetState() {
		case kmspb.CryptoKeyVersion_ENABLED:
			return version, nil
		case kmspb.CryptoKeyVersion_IMPORT_FAILED:
			return nil, fmt.Errorf("GCP key import failed: %s", version.GetImportFailureReason())
		case kmspb.CryptoKeyVersion_PENDING_IMPORT, kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED:
			// Still importing; keep polling below.
		default:
			return nil, fmt.Errorf("unexpected CryptoKeyVersion state after import: %s", version.GetState())
		}
		if waited >= p.pollMaxWait {
			return nil, fmt.Errorf("timed out waiting for %s to become ENABLED (last state: %s)", version.GetName(), version.GetState())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(p.pollInterval):
			waited += p.pollInterval
		}
		refreshed, err := p.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: version.GetName()})
		if err != nil {
			return nil, fmt.Errorf("failed to get CryptoKeyVersion state: %w", err)
		}
		version = refreshed
	}
}

type gcpSigner struct {
	client         GCPKMSClient
	keyVersionName string
}

// crc32cTable is the Castagnoli polynomial table used by Cloud KMS for
// end-to-end integrity verification.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) int64 {
	return int64(crc32.Checksum(data, crc32cTable))
}

func (s *gcpSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	signOut, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyVersionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest},
		},
		DigestCrc32C: wrapperspb.Int64(crc32c(digest)),
	})
	if err != nil {
		return nil, err
	}
	// End-to-end integrity verification as recommended by Cloud KMS docs.
	if signOut.GetName() != s.keyVersionName {
		return nil, fmt.Errorf("AsymmetricSign response is for %q, want %q: request may have been modified in transit", signOut.GetName(), s.keyVersionName)
	}
	if !signOut.GetVerifiedDigestCrc32C() {
		return nil, fmt.Errorf("AsymmetricSign request digest checksum was not verified by Cloud KMS: request may have been corrupted in transit")
	}
	if signOut.GetSignatureCrc32C().GetValue() != crc32c(signOut.GetSignature()) {
		return nil, fmt.Errorf("AsymmetricSign response signature checksum mismatch: response may have been corrupted in transit")
	}
	return signOut.GetSignature(), nil
}
