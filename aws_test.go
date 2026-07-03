package main

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestAWSProvider_EmptyPublicKey(t *testing.T) {
	mock := &mockKMSClient{
		getParametersForImportFn: func(context.Context, *kms.GetParametersForImportInput, ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
			return &kms.GetParametersForImportOutput{
				PublicKey:   nil,
				ImportToken: []byte("t"),
			}, nil
		},
	}

	_, err := newAWSProvider(mock, "k").WrappingPublicKeyDER(context.Background())
	if err == nil {
		t.Fatal("expected empty public key error, got nil")
	}
	if !strings.Contains(err.Error(), "empty wrapping public key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAWSProvider_EmptyImportToken(t *testing.T) {
	mock := &mockKMSClient{
		getParametersForImportFn: func(context.Context, *kms.GetParametersForImportInput, ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
			return &kms.GetParametersForImportOutput{
				PublicKey:   []byte("pub"),
				ImportToken: nil,
			}, nil
		},
	}

	_, err := newAWSProvider(mock, "k").WrappingPublicKeyDER(context.Background())
	if err == nil {
		t.Fatal("expected empty import token error, got nil")
	}
	if !strings.Contains(err.Error(), "empty import token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAWSProvider_ImportWithoutToken(t *testing.T) {
	p := newAWSProvider(&mockKMSClient{}, "k")

	_, _, err := p.ImportKeyMaterial(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("expected missing import token error, got nil")
	}
	if !strings.Contains(err.Error(), "import token is missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}
