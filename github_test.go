package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestValidateWithGitHub_Success(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	appID := 12345
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has a JWT in Authorization header.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer prefix in Authorization header")
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("JWT should have 3 parts, got %d", len(parts))
		}

		// Verify JWT header.
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var header map[string]string
		json.Unmarshal(headerJSON, &header)
		if header["alg"] != "RS256" || header["typ"] != "JWT" {
			t.Errorf("unexpected JWT header: %v", header)
		}

		// Verify JWT payload.
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload map[string]any
		json.Unmarshal(payloadJSON, &payload)
		if int(payload["iss"].(float64)) != appID {
			t.Errorf("unexpected iss: %v", payload["iss"])
		}

		// Verify JWT signature.
		sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			t.Errorf("JWT signature verification failed: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": appID, "name": "test-app"})
	}))
	defer server.Close()

	mock := newTestSignerMock(t, privKey)
	var stdout bytes.Buffer
	err = validateWithGitHub(context.Background(), mock, server.Client(), &stdout, server.URL, "test-key-id", appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Authentication successful") {
		t.Errorf("expected success message in output, got: %s", stdout.String())
	}
}

func TestValidateWithGitHub_KMSSignError(t *testing.T) {
	mock := &mockKMSClient{
		signFn: func(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}

	err := validateWithGitHub(context.Background(), mock, http.DefaultClient, io.Discard, "https://api.github.com", "key-id", 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "KMS signing failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateWithGitHub_GitHubAPIError(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	mock := newTestSignerMock(t, privKey)
	err := validateWithGitHub(context.Background(), mock, server.Client(), io.Discard, server.URL, "key-id", 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "GitHub API error (HTTP 401)") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateWithGitHub_AppIDMismatch(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 99999, "name": "wrong-app"})
	}))
	defer server.Close()

	mock := newTestSignerMock(t, privKey)
	err := validateWithGitHub(context.Background(), mock, server.Client(), io.Discard, server.URL, "key-id", 12345)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "app ID mismatch") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateWithGitHub_InvalidJSON(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	mock := newTestSignerMock(t, privKey)
	err := validateWithGitHub(context.Background(), mock, server.Client(), io.Discard, server.URL, "key-id", 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse response") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "aGVsbG8"},
		{[]byte{0xff, 0xfe}, "__4"}, // URL-safe: _ instead of /
		{[]byte{0xfb, 0xef}, "--8"}, // URL-safe: - instead of +
		{[]byte{0, 0, 0}, "AAAA"},   // No padding
		{[]byte(`{"alg":"RS256"}`), "eyJhbGciOiJSUzI1NiJ9"},
	}
	for _, tt := range tests {
		got := base64URLEncode(tt.input)
		if got != tt.expected {
			t.Errorf("base64URLEncode(%v) = %q, want %q", tt.input, got, tt.expected)
		}
		// Verify no padding characters.
		if strings.Contains(got, "=") {
			t.Errorf("base64URLEncode(%v) contains padding: %q", tt.input, got)
		}
	}
}
