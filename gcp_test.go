package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

const (
	testGCPKeyName        = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
	testGCPImportJobName  = "projects/p/locations/global/keyRings/r/importJobs/j"
	testGCPKeyVersionName = testGCPKeyName + "/cryptoKeyVersions/1"
)

func TestRun_GCPImportsAndVerifies(t *testing.T) {
	fakeKMS := newFakeGCPKMSClient(t)

	appID := 12345
	githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			t.Errorf("unexpected GitHub path: %s", r.URL.Path)
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT should have 3 parts, got %d", len(parts))
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("invalid JWT signature encoding: %v", err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(fakeKMS.importedPublicKey(t), crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("JWT signature did not verify with imported key: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"id": appID, "name": "fake-gcp-app"}); err != nil {
			t.Fatal(err)
		}
	}))
	defer githubServer.Close()

	var stdout bytes.Buffer
	err := run(context.Background(), newGCPProvider(fakeKMS, testGCPKeyName, testGCPImportJobName), githubServer.Client(), strings.NewReader("n\n"), &stdout, runConfig{
		GitHubBaseURL: githubServer.URL,
		PEMFile:       "testdata/pkcs1.pem",
		AppID:         &appID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantDER, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fakeKMS.importedDER(t), wantDER) {
		t.Fatal("imported key material does not match PEM converted to PKCS#8 DER")
	}
	fakeKMS.assertCalls(t, 1, 1, 1)

	output := stdout.String()
	for _, want := range []string{"KMS import complete", "Authentication successful", "Done"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %q in output, got: %s", want, output)
		}
	}
}

func TestGCPProvider_UnsupportedImportMethod(t *testing.T) {
	fakeKMS := newFakeGCPKMSClient(t)
	fakeKMS.importMethod = kmspb.ImportJob_RSA_OAEP_4096_SHA1_AES_256

	_, err := newGCPProvider(fakeKMS, testGCPKeyName, testGCPImportJobName).WrappingPublicKeyDER(context.Background())
	if err == nil {
		t.Fatal("expected unsupported import method error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported GCP import method") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_GCPDryRunSkipsImport(t *testing.T) {
	fakeKMS := newFakeGCPKMSClient(t)

	var stdout bytes.Buffer
	err := run(context.Background(), newGCPProvider(fakeKMS, testGCPKeyName, testGCPImportJobName), http.DefaultClient, strings.NewReader(""), &stdout, runConfig{
		GitHubBaseURL: "https://api.github.com",
		PEMFile:       "testdata/pkcs1.pem",
		DryRun:        true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fakeKMS.assertCalls(t, 1, 0, 0)
	output := stdout.String()
	if !strings.Contains(output, "Dry run complete") {
		t.Errorf("expected dry-run message in output, got: %s", output)
	}
	if strings.Contains(output, "Importing into KMS") {
		t.Error("should not attempt import in dry-run mode")
	}
}

type fakeGCPKMSClient struct {
	t            *testing.T
	wrappingKey  *rsa.PrivateKey
	importMethod kmspb.ImportJob_ImportMethod

	mu          sync.Mutex
	importedKey *rsa.PrivateKey
	importedRaw []byte
	getCalls    int
	importCalls int
	signCalls   int
}

func newFakeGCPKMSClient(t *testing.T) *fakeGCPKMSClient {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeGCPKMSClient{
		t:            t,
		wrappingKey:  wrappingKey,
		importMethod: kmspb.ImportJob_RSA_OAEP_4096_SHA256_AES_256,
	}
}

func (f *fakeGCPKMSClient) GetImportJob(_ context.Context, req *kmspb.GetImportJobRequest, _ ...gax.CallOption) (*kmspb.ImportJob, error) {
	if req.GetName() != testGCPImportJobName {
		f.t.Errorf("unexpected import job name: %s", req.GetName())
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&f.wrappingKey.PublicKey)
	if err != nil {
		f.t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	f.mu.Lock()
	f.getCalls++
	f.mu.Unlock()

	return &kmspb.ImportJob{
		Name:         req.GetName(),
		ImportMethod: f.importMethod,
		State:        kmspb.ImportJob_ACTIVE,
		PublicKey:    &kmspb.ImportJob_WrappingPublicKey{Pem: string(pubPEM)},
	}, nil
}

func (f *fakeGCPKMSClient) ImportCryptoKeyVersion(_ context.Context, req *kmspb.ImportCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	if req.GetParent() != testGCPKeyName {
		f.t.Errorf("unexpected parent: %s", req.GetParent())
	}
	if req.GetImportJob() != testGCPImportJobName {
		f.t.Errorf("unexpected import job: %s", req.GetImportJob())
	}
	if req.GetAlgorithm() != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
		f.t.Errorf("unexpected algorithm: %s", req.GetAlgorithm())
	}
	if req.GetWrappedKeyMaterial() != nil {
		f.t.Errorf("rsa_aes_wrapped_key should not be set when using wrapped_key")
	}
	encrypted := req.GetWrappedKey()
	if len(encrypted) == 0 {
		f.t.Fatal("empty wrapped_key")
	}

	keyDER, err := f.decryptImportedKeyMaterial(encrypted)
	if err != nil {
		f.t.Fatalf("failed to decrypt imported key material: %v", err)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		f.t.Fatalf("imported key material is not PKCS#8 DER: %v", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		f.t.Fatalf("imported key is %T, want *rsa.PrivateKey", keyAny)
	}

	f.mu.Lock()
	f.importCalls++
	f.importedKey = key
	f.importedRaw = bytes.Clone(keyDER)
	f.mu.Unlock()

	return &kmspb.CryptoKeyVersion{Name: testGCPKeyVersionName}, nil
}

func (f *fakeGCPKMSClient) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if req.GetName() != testGCPKeyVersionName {
		f.t.Errorf("unexpected key version name: %s", req.GetName())
	}
	digest := req.GetDigest().GetSha256()
	if len(digest) != sha256.Size {
		f.t.Fatalf("unexpected SHA-256 digest length: %d", len(digest))
	}

	f.mu.Lock()
	key := f.importedKey
	f.signCalls++
	f.mu.Unlock()
	if key == nil {
		f.t.Fatal("AsymmetricSign called before key material was imported")
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		f.t.Fatalf("failed to sign digest: %v", err)
	}
	return &kmspb.AsymmetricSignResponse{Name: req.GetName(), Signature: sig}, nil
}

func (f *fakeGCPKMSClient) decryptImportedKeyMaterial(encrypted []byte) ([]byte, error) {
	rsaCiphertextLen := f.wrappingKey.Size()
	if len(encrypted) <= rsaCiphertextLen {
		return nil, fmt.Errorf("encrypted material too short: %d", len(encrypted))
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.wrappingKey, encrypted[:rsaCiphertextLen], nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP unwrap failed: %w", err)
	}
	keyDER, err := aesKeyUnwrapWithPadding(aesKey, encrypted[rsaCiphertextLen:])
	if err != nil {
		return nil, fmt.Errorf("AES key unwrap failed: %w", err)
	}
	return keyDER, nil
}

func (f *fakeGCPKMSClient) importedDER(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importedRaw == nil {
		t.Fatal("no imported key material")
	}
	return bytes.Clone(f.importedRaw)
}

func (f *fakeGCPKMSClient) importedPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importedKey == nil {
		t.Fatal("no imported key material")
	}
	return &f.importedKey.PublicKey
}

func (f *fakeGCPKMSClient) assertCalls(t *testing.T, get, importKey, sign int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getCalls != get || f.importCalls != importKey || f.signCalls != sign {
		t.Fatalf("unexpected GCP KMS calls: get=%d import=%d sign=%d", f.getCalls, f.importCalls, f.signCalls)
	}
}
