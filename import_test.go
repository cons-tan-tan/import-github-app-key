package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestEncryptKeyMaterial_ValidOutput(t *testing.T) {
	// Generate an RSA-4096 wrapping key pair for testing.
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	wrappingPubDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Use the test PEM fixture to get a realistic private key DER.
	privateKeyDER, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}

	result, err := encryptKeyMaterial(privateKeyDER, wrappingPubDER)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The output should be: RSA-4096 ciphertext (512 bytes) + AES-wrapped key.
	rsaCiphertextLen := 4096 / 8 // 512 bytes
	if len(result) <= rsaCiphertextLen {
		t.Fatalf("output too short: %d bytes (expected > %d)", len(result), rsaCiphertextLen)
	}

	// Verify the RSA-encrypted portion can be decrypted to a 32-byte AES key.
	encryptedAESKey := result[:rsaCiphertextLen]
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		wrappingKey,
		encryptedAESKey,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to decrypt AES key: %v", err)
	}
	if len(aesKey) != 32 {
		t.Errorf("expected 32-byte AES key, got %d bytes", len(aesKey))
	}
}

func TestEncryptKeyMaterial_InvalidWrappingKey(t *testing.T) {
	privateKeyDER, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}

	_, err = encryptKeyMaterial(privateKeyDER, []byte("not a valid DER"))
	if err == nil {
		t.Fatal("expected error for invalid wrapping key, got nil")
	}
}

func TestEncryptKeyMaterial_NonRSAWrappingKey(t *testing.T) {
	privateKeyDER, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}

	// Use an EC key instead of RSA.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = encryptKeyMaterial(privateKeyDER, ecPubDER)
	if err == nil {
		t.Fatal("expected error for non-RSA wrapping key, got nil")
	}
}

func TestRun_Success(t *testing.T) {
	mock := newWrappingKeyMock(t)

	var stdout bytes.Buffer
	stdin := strings.NewReader("n\n")

	err := run(context.Background(), mock, http.DefaultClient, stdin, &stdout, runConfig{
		GitHubBaseURL: "https://api.github.com",
		KeyID:         "test-key-id",
		PEMFile:       "testdata/pkcs1.pem",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "KMS import complete") {
		t.Errorf("expected 'KMS import complete' in output, got: %s", output)
	}
	if !strings.Contains(output, "Done") {
		t.Errorf("expected 'Done' in output, got: %s", output)
	}
	// Verify GitHub validation was skipped (appID is nil).
	if strings.Contains(output, "Validating with GitHub API") {
		t.Error("GitHub validation should not run when appID is nil")
	}
}

func TestRun_DeletePEM(t *testing.T) {
	// Copy testdata PEM to a temp file.
	data, err := os.ReadFile("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tmpPEM := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(tmpPEM, data, 0o600); err != nil {
		t.Fatal(err)
	}

	mock := newWrappingKeyMock(t)

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")

	err = run(context.Background(), mock, http.DefaultClient, stdin, &stdout, runConfig{
		GitHubBaseURL: "https://api.github.com",
		KeyID:         "test-key-id",
		PEMFile:       tmpPEM,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the PEM file was deleted.
	if _, err := os.Stat(tmpPEM); !os.IsNotExist(err) {
		t.Error("PEM file should have been deleted")
	}
	if !strings.Contains(stdout.String(), "Deleted:") {
		t.Error("expected deletion message in output")
	}
}

func TestRun_DeleteFlag(t *testing.T) {
	// Copy testdata PEM to a temp file.
	data, err := os.ReadFile("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tmpPEM := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(tmpPEM, data, 0o600); err != nil {
		t.Fatal(err)
	}

	mock := newWrappingKeyMock(t)

	var stdout bytes.Buffer
	// stdin is empty — no interactive input needed when --delete is set.
	stdin := strings.NewReader("")

	err = run(context.Background(), mock, http.DefaultClient, stdin, &stdout, runConfig{
		GitHubBaseURL: "https://api.github.com",
		KeyID:         "test-key-id",
		PEMFile:       tmpPEM,
		DeletePEM:     true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(tmpPEM); !os.IsNotExist(err) {
		t.Error("PEM file should have been deleted with --delete flag")
	}
	output := stdout.String()
	// Should not contain the interactive prompt.
	if strings.Contains(output, "Delete PEM file? [y/N]") {
		t.Error("should not prompt when --delete flag is set")
	}
	if !strings.Contains(output, "Deleted:") {
		t.Error("expected deletion message in output")
	}
}

func TestRun_DryRun(t *testing.T) {
	importCalled := false
	mock := newWrappingKeyMock(t)
	mock.importKeyMaterialFn = func(_ context.Context, _ *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
		importCalled = true
		return &kms.ImportKeyMaterialOutput{}, nil
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("")

	err := run(context.Background(), mock, http.DefaultClient, stdin, &stdout, runConfig{
		GitHubBaseURL: "https://api.github.com",
		KeyID:         "test-key-id",
		PEMFile:       "testdata/pkcs1.pem",
		DryRun:        true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if importCalled {
		t.Error("ImportKeyMaterial should not be called in dry-run mode")
	}
	output := stdout.String()
	if !strings.Contains(output, "Dry run complete") {
		t.Errorf("expected 'Dry run complete' in output, got: %s", output)
	}
	if strings.Contains(output, "Importing into KMS") {
		t.Error("should not attempt import in dry-run mode")
	}
}
