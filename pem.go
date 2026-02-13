package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// pemToPKCS8DER reads a PEM file containing an RSA private key (PKCS#1 or PKCS#8)
// and returns the key in PKCS#8 DER format.
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

	return x509.MarshalPKCS8PrivateKey(key)
}
