package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// mockKMSClient implements KMSClient for testing.
type mockKMSClient struct {
	getParametersForImportFn func(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	importKeyMaterialFn      func(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	signFn                   func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSClient) GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
	if m.getParametersForImportFn != nil {
		return m.getParametersForImportFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("GetParametersForImport not implemented")
}

func (m *mockKMSClient) ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
	if m.importKeyMaterialFn != nil {
		return m.importKeyMaterialFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("ImportKeyMaterial not implemented")
}

func (m *mockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.signFn != nil {
		return m.signFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("Sign not implemented")
}

// newTestSignerMock creates a mockKMSClient that signs with the given RSA private key.
func newTestSignerMock(t *testing.T, privKey *rsa.PrivateKey) *mockKMSClient {
	t.Helper()
	return &mockKMSClient{
		signFn: func(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
			if params.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
				return nil, fmt.Errorf("unexpected algorithm: %s", params.SigningAlgorithm)
			}
			sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, params.Message)
			if err != nil {
				return nil, err
			}
			return &kms.SignOutput{Signature: sig}, nil
		},
	}
}

// newWrappingKeyMock creates a mockKMSClient that handles GetParametersForImport
// and ImportKeyMaterial for integration testing of run().
func newWrappingKeyMock(t *testing.T) *mockKMSClient {
	t.Helper()

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	wrappingPubDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	importToken := []byte("test-import-token")

	return &mockKMSClient{
		getParametersForImportFn: func(_ context.Context, params *kms.GetParametersForImportInput, _ ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
			if params.WrappingAlgorithm != types.AlgorithmSpecRsaAesKeyWrapSha256 {
				t.Errorf("unexpected wrapping algorithm: %s", params.WrappingAlgorithm)
			}
			return &kms.GetParametersForImportOutput{
				PublicKey:   wrappingPubDER,
				ImportToken: importToken,
			}, nil
		},
		importKeyMaterialFn: func(_ context.Context, params *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
			if !bytes.Equal(params.ImportToken, importToken) {
				t.Error("unexpected import token")
			}
			if len(params.EncryptedKeyMaterial) == 0 {
				t.Error("empty encrypted key material")
			}
			return &kms.ImportKeyMaterialOutput{}, nil
		},
	}
}
