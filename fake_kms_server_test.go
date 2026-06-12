package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestRun_WithFakeKMSServer_ImportsAndVerifiesWithRealSDK(t *testing.T) {
	fakeKMS := newFakeKMSServer(t)
	defer fakeKMS.Close()

	client := kms.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  fakeKMS.Client(),
	}, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(fakeKMS.URL)
	})

	appID := 12345
	githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			t.Errorf("unexpected GitHub path: %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer token")
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT should have 3 parts, got %d", len(parts))
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("invalid JWT signature encoding: %v", err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		pub := fakeKMS.importedPublicKey(t)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("JWT signature did not verify with imported key: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"id": appID, "name": "fake-app"}); err != nil {
			t.Fatal(err)
		}
	}))
	defer githubServer.Close()

	var stdout bytes.Buffer
	err := run(context.Background(), newAWSProvider(client, "fake-key-id"), githubServer.Client(), strings.NewReader("n\n"), &stdout, runConfig{
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

type fakeKMSServer struct {
	*httptest.Server

	t           *testing.T
	wrappingKey *rsa.PrivateKey
	importToken []byte

	mu          sync.Mutex
	importedKey *rsa.PrivateKey
	importedRaw []byte
	getCalls    int
	importCalls int
	signCalls   int
}

func newFakeKMSServer(t *testing.T) *fakeKMSServer {
	t.Helper()

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	fake := &fakeKMSServer{
		t:           t,
		wrappingKey: wrappingKey,
		importToken: []byte("fake-import-token"),
	}
	fake.Server = httptest.NewServer(http.HandlerFunc(fake.handle))
	return fake
}

func (f *fakeKMSServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.GetParametersForImport":
		f.handleGetParametersForImport(w, r)
	case "TrentService.ImportKeyMaterial":
		f.handleImportKeyMaterial(w, r)
	case "TrentService.Sign":
		f.handleSign(w, r)
	default:
		http.Error(w, "unsupported target", http.StatusBadRequest)
	}
}

func (f *fakeKMSServer) handleGetParametersForImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID             string `json:"KeyId"`
		WrappingAlgorithm string `json:"WrappingAlgorithm"`
		WrappingKeySpec   string `json:"WrappingKeySpec"`
	}
	decodeJSON(f.t, r, &req)
	if req.KeyID != "fake-key-id" {
		f.t.Errorf("unexpected KeyId: %s", req.KeyID)
	}
	if req.WrappingAlgorithm != "RSA_AES_KEY_WRAP_SHA_256" {
		f.t.Errorf("unexpected WrappingAlgorithm: %s", req.WrappingAlgorithm)
	}
	if req.WrappingKeySpec != "RSA_4096" {
		f.t.Errorf("unexpected WrappingKeySpec: %s", req.WrappingKeySpec)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&f.wrappingKey.PublicKey)
	if err != nil {
		f.t.Fatal(err)
	}

	f.mu.Lock()
	f.getCalls++
	f.mu.Unlock()

	writeJSON(f.t, w, map[string]any{
		"KeyId":       "fake-key-id",
		"PublicKey":   base64.StdEncoding.EncodeToString(pubDER),
		"ImportToken": base64.StdEncoding.EncodeToString(f.importToken),
	})
}

func (f *fakeKMSServer) handleImportKeyMaterial(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID                string `json:"KeyId"`
		EncryptedKeyMaterial string `json:"EncryptedKeyMaterial"`
		ImportToken          string `json:"ImportToken"`
		ExpirationModel      string `json:"ExpirationModel"`
	}
	decodeJSON(f.t, r, &req)
	if req.KeyID != "fake-key-id" {
		f.t.Errorf("unexpected KeyId: %s", req.KeyID)
	}
	if req.ExpirationModel != "KEY_MATERIAL_DOES_NOT_EXPIRE" {
		f.t.Errorf("unexpected ExpirationModel: %s", req.ExpirationModel)
	}
	token, err := base64.StdEncoding.DecodeString(req.ImportToken)
	if err != nil {
		f.t.Fatalf("invalid import token encoding: %v", err)
	}
	if !bytes.Equal(token, f.importToken) {
		f.t.Fatalf("unexpected import token: %q", token)
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedKeyMaterial)
	if err != nil {
		f.t.Fatalf("invalid encrypted key material encoding: %v", err)
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

	writeJSON(f.t, w, map[string]any{"KeyId": "fake-key-id"})
}

func (f *fakeKMSServer) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID            string `json:"KeyId"`
		Message          string `json:"Message"`
		MessageType      string `json:"MessageType"`
		SigningAlgorithm string `json:"SigningAlgorithm"`
	}
	decodeJSON(f.t, r, &req)
	if req.KeyID != "fake-key-id" {
		f.t.Errorf("unexpected KeyId: %s", req.KeyID)
	}
	if req.MessageType != "DIGEST" {
		f.t.Errorf("unexpected MessageType: %s", req.MessageType)
	}
	if req.SigningAlgorithm != "RSASSA_PKCS1_V1_5_SHA_256" {
		f.t.Errorf("unexpected SigningAlgorithm: %s", req.SigningAlgorithm)
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		f.t.Fatalf("invalid message encoding: %v", err)
	}

	f.mu.Lock()
	key := f.importedKey
	f.signCalls++
	f.mu.Unlock()
	if key == nil {
		f.t.Fatal("Sign called before key material was imported")
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, message)
	if err != nil {
		f.t.Fatalf("failed to sign digest: %v", err)
	}

	writeJSON(f.t, w, map[string]any{
		"KeyId":            "fake-key-id",
		"Signature":        base64.StdEncoding.EncodeToString(sig),
		"SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
	})
}

func (f *fakeKMSServer) decryptImportedKeyMaterial(encrypted []byte) ([]byte, error) {
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

func (f *fakeKMSServer) importedDER(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importedRaw == nil {
		t.Fatal("no imported key material")
	}
	return bytes.Clone(f.importedRaw)
}

func (f *fakeKMSServer) importedPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importedKey == nil {
		t.Fatal("no imported key material")
	}
	return &f.importedKey.PublicKey
}

func (f *fakeKMSServer) assertCalls(t *testing.T, get, importKey, sign int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getCalls != get || f.importCalls != importKey || f.signCalls != sign {
		t.Fatalf("unexpected KMS calls: get=%d import=%d sign=%d", f.getCalls, f.importCalls, f.signCalls)
	}
}

func decodeJSON(t *testing.T, r *http.Request, v any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("failed to decode request JSON: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

func aesKeyUnwrapWithPadding(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("wrapped key must be at least 16 bytes and a multiple of 8")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	if len(wrapped) == 16 {
		buf := bytes.Clone(wrapped)
		block.Decrypt(buf, buf)
		return validateAndUnpadRFC5649(buf[:8], buf[8:])
	}

	n := (len(wrapped) / 8) - 1
	a := bytes.Clone(wrapped[:8])
	r := make([][]byte, n)
	for i := range n {
		r[i] = bytes.Clone(wrapped[8+(i*8) : 16+(i*8)])
	}

	buf := make([]byte, aes.BlockSize)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			aXorT := binary.BigEndian.Uint64(a) ^ t
			binary.BigEndian.PutUint64(buf[:8], aXorT)
			copy(buf[8:], r[i-1])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}

	padded := make([]byte, 0, n*8)
	for _, block := range r {
		padded = append(padded, block...)
	}
	return validateAndUnpadRFC5649(a, padded)
}

func validateAndUnpadRFC5649(aiv, padded []byte) ([]byte, error) {
	if len(aiv) != 8 {
		return nil, fmt.Errorf("invalid AIV length: %d", len(aiv))
	}
	if !bytes.Equal(aiv[:4], []byte{0xa6, 0x59, 0x59, 0xa6}) {
		return nil, fmt.Errorf("invalid AIV constant: %x", aiv[:4])
	}

	messageLen := int(binary.BigEndian.Uint32(aiv[4:]))
	if messageLen < 0 || messageLen > len(padded) {
		return nil, fmt.Errorf("invalid message length: %d", messageLen)
	}
	paddingLen := len(padded) - messageLen
	if paddingLen > 7 {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}
	for _, b := range padded[messageLen:] {
		if b != 0 {
			return nil, fmt.Errorf("invalid non-zero padding")
		}
	}
	return bytes.Clone(padded[:messageLen]), nil
}
