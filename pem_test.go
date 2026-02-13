package main

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// Test keys under testdata/ are generated solely for testing and are not used in any real environment.

func TestPemToPKCS8DER_PKCS1(t *testing.T) {
	der, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("output is not valid PKCS#8: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d", rsaKey.N.BitLen())
	}
}

func TestPemToPKCS8DER_PKCS8(t *testing.T) {
	der, err := pemToPKCS8DER("testdata/pkcs8.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("output is not valid PKCS#8: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatal("parsed key is not RSA")
	}
}

func TestPemToPKCS8DER_BothFormatsProduceSameKey(t *testing.T) {
	der1, err := pemToPKCS8DER("testdata/pkcs1.pem")
	if err != nil {
		t.Fatalf("PKCS#1: %v", err)
	}
	der8, err := pemToPKCS8DER("testdata/pkcs8.pem")
	if err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}

	key1, _ := x509.ParsePKCS8PrivateKey(der1)
	key8, _ := x509.ParsePKCS8PrivateKey(der8)

	rsaKey1 := key1.(*rsa.PrivateKey)
	rsaKey8 := key8.(*rsa.PrivateKey)

	if rsaKey1.N.Cmp(rsaKey8.N) != 0 {
		t.Error("PKCS#1 and PKCS#8 inputs produced different keys")
	}
}

func TestPemToPKCS8DER_FileNotFound(t *testing.T) {
	_, err := pemToPKCS8DER("testdata/nonexistent.pem")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestPemToPKCS8DER_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := pemToPKCS8DER(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestPemToPKCS8DER_UnsupportedType(t *testing.T) {
	// Create a PEM file with an unsupported type header.
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	content := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := pemToPKCS8DER(path)
	if err == nil {
		t.Fatal("expected error for unsupported PEM type, got nil")
	}
}
