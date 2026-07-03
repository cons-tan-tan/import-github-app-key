package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClient is the subset of AWS kms.Client methods used by this tool.
type KMSClient interface {
	GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

type awsProvider struct {
	client      KMSClient
	keyID       string
	importToken []byte
}

func newAWSProvider(client KMSClient, keyID string) *awsProvider {
	return &awsProvider{client: client, keyID: keyID}
}

func (p *awsProvider) WrappingPublicKeyDER(ctx context.Context) ([]byte, error) {
	params, err := p.client.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
		KeyId:             &p.keyID,
		WrappingAlgorithm: types.AlgorithmSpecRsaAesKeyWrapSha256,
		WrappingKeySpec:   types.WrappingKeySpecRsa4096,
	})
	if err != nil {
		return nil, err
	}
	if len(params.PublicKey) == 0 {
		return nil, fmt.Errorf("AWS KMS returned an empty wrapping public key")
	}
	if len(params.ImportToken) == 0 {
		return nil, fmt.Errorf("AWS KMS returned an empty import token")
	}
	p.importToken = params.ImportToken
	return params.PublicKey, nil
}

func (p *awsProvider) ImportKeyMaterial(ctx context.Context, encrypted []byte) (digestSigner, string, error) {
	if len(p.importToken) == 0 {
		return nil, "", fmt.Errorf("AWS import token is missing; fetch wrapping parameters first")
	}
	_, err := p.client.ImportKeyMaterial(ctx, &kms.ImportKeyMaterialInput{
		KeyId:                &p.keyID,
		EncryptedKeyMaterial: encrypted,
		ImportToken:          p.importToken,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	})
	if err != nil {
		return nil, "", err
	}
	return &awsSigner{client: p.client, keyID: p.keyID}, p.keyID, nil
}

type awsSigner struct {
	client KMSClient
	keyID  string
}

func (s *awsSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	signOut, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:       &s.keyID,
		Message:     digest,
		MessageType: types.MessageTypeDigest,
		// RS256 (RFC 7518) corresponds to RSASSA-PKCS1-v1_5 using SHA-256.
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, err
	}
	return signOut.Signature, nil
}
