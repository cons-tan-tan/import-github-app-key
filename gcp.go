package main

import (
	"context"
	"encoding/pem"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// GCPKMSClient is the subset of Cloud KMS client methods used by this tool.
type GCPKMSClient interface {
	GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...gax.CallOption) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

type gcpProvider struct {
	client        GCPKMSClient
	cryptoKeyName string
	importJobName string
}

func newGCPProvider(client GCPKMSClient, cryptoKeyName, importJobName string) *gcpProvider {
	return &gcpProvider{
		client:        client,
		cryptoKeyName: cryptoKeyName,
		importJobName: importJobName,
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

func (p *gcpProvider) ImportKeyMaterial(ctx context.Context, encrypted []byte) (digestSigner, error) {
	version, err := p.client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     p.cryptoKeyName,
		Algorithm:  kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		ImportJob:  p.importJobName,
		WrappedKey: encrypted,
	})
	if err != nil {
		return nil, err
	}
	keyVersionName := version.GetName()
	if keyVersionName == "" {
		return nil, fmt.Errorf("GCP import returned an empty CryptoKeyVersion name")
	}
	return &gcpSigner{client: p.client, keyVersionName: keyVersionName}, nil
}

type gcpSigner struct {
	client         GCPKMSClient
	keyVersionName string
}

func (s *gcpSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	signOut, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyVersionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest},
		},
	})
	if err != nil {
		return nil, err
	}
	return signOut.GetSignature(), nil
}
