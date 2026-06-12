package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// pemToPKCS8DER reads a PEM file containing an RSA private key (PKCS#1 or PKCS#8),
// validates that the key is RSA 2048-bit, and returns the key in PKCS#8 DER format.
func pemToPKCS8DER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key (got %T): GitHub App keys are RSA", key)
	}
	if bits := rsaKey.N.BitLen(); bits != 2048 {
		return nil, fmt.Errorf("unexpected RSA key size: %d bits (GitHub App keys are 2048-bit; the KMS key must be RSA_2048)", bits)
	}

	return x509.MarshalPKCS8PrivateKey(rsaKey)
}
