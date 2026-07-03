package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// runConfig holds the user-specified parameters for the import workflow.
type runConfig struct {
	GitHubBaseURL string
	PEMFile       string
	AppID         *int
	DeletePEM     bool
	DryRun        bool
}

// run orchestrates the full import workflow:
//  1. Convert PEM to PKCS#8 DER
//  2. Fetch KMS wrapping parameters
//  3. Encrypt the private key for import
//  4. Import the key material into KMS
//  5. (Optional) Validate the imported key by signing a JWT and calling the GitHub API
//  6. Optionally delete the PEM file
func run(ctx context.Context, provider keyImportProvider, httpClient *http.Client, stdin io.Reader, stdout io.Writer, cfg runConfig) error {
	// Step 1: PEM -> PKCS#8 DER
	privateKeyDER, err := pemToPKCS8DER(cfg.PEMFile)
	if err != nil {
		return fmt.Errorf("PEM conversion failed: %w", err)
	}
	defer func() {
		for i := range privateKeyDER {
			privateKeyDER[i] = 0
		}
	}()
	fmt.Fprintln(stdout, "PEM -> PKCS#8 DER conversion complete")

	// Step 2: Fetch KMS wrapping parameters
	fmt.Fprintln(stdout, "Fetching KMS wrapping parameters...")
	wrappingPublicKeyDER, err := provider.WrappingPublicKeyDER(ctx)
	if err != nil {
		return fmt.Errorf("failed to get wrapping parameters: %w", err)
	}

	// Step 3: Encrypt the private key
	fmt.Fprintln(stdout, "Encrypting private key...")
	encrypted, err := encryptKeyMaterial(privateKeyDER, wrappingPublicKeyDER)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if cfg.DryRun {
		fmt.Fprintln(stdout, "Dry run complete (skipping import)")
		return nil
	}

	// Step 4: Import into KMS
	fmt.Fprintln(stdout, "Importing into KMS...")
	signer, keyRef, err := provider.ImportKeyMaterial(ctx, encrypted)
	if err != nil {
		return fmt.Errorf("KMS import failed: %w", err)
	}
	fmt.Fprintf(stdout, "KMS import complete: %s\n", keyRef)

	// Step 5: Validate with GitHub API (only if --verify is specified)
	if cfg.AppID != nil {
		fmt.Fprintln(stdout, "\nValidating with GitHub API...")
		if err := validateWithGitHub(ctx, signer, httpClient, stdout, cfg.GitHubBaseURL, *cfg.AppID); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Step 6: Optionally delete the PEM file
	shouldDelete := cfg.DeletePEM
	if !shouldDelete {
		fmt.Fprint(stdout, "\nDelete PEM file? [y/N]: ")
		scanner := bufio.NewScanner(stdin)
		shouldDelete = scanner.Scan() && strings.EqualFold(strings.TrimSpace(scanner.Text()), "y")
	}
	if shouldDelete {
		if err := os.Remove(cfg.PEMFile); err != nil {
			return fmt.Errorf("failed to delete PEM file: %w", err)
		}
		fmt.Fprintf(stdout, "Deleted: %s\n", cfg.PEMFile)
	}

	fmt.Fprintln(stdout, "Done")
	return nil
}

// encryptKeyMaterial encrypts a private key for KMS import using RSA_AES_KEY_WRAP_SHA_256:
//  1. Generate a random AES-256 key
//  2. Wrap the private key with AES Key Wrap with Padding (RFC 5649)
//  3. Encrypt the AES key with RSA-OAEP (SHA-256) using the KMS wrapping public key
//  4. Return the concatenation: encrypted AES key || wrapped private key
func encryptKeyMaterial(privateKeyDER, wrappingPublicKeyDER []byte) ([]byte, error) {
	aesKey := make([]byte, 32)
	defer func() {
		for i := range aesKey {
			aesKey[i] = 0
		}
	}()
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	wrappedKey, err := aesKeyWrapWithPadding(aesKey, privateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("AES key wrap failed: %w", err)
	}

	pubKeyAny, err := x509.ParsePKIXPublicKey(wrappingPublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wrapping public key: %w", err)
	}
	rsaPubKey, ok := pubKeyAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrapping key is not RSA")
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	result := make([]byte, 0, len(encryptedAESKey)+len(wrappedKey))
	result = append(result, encryptedAESKey...)
	result = append(result, wrappedKey...)
	return result, nil
}
