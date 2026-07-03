package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// validateWithGitHub signs a JWT using the KMS key and verifies it against the
// GitHub API (GET /app). This confirms the imported key is valid for the given app.
func validateWithGitHub(ctx context.Context, signer digestSigner, httpClient *http.Client, stdout io.Writer, githubBaseURL string, appID int) error {
	now := time.Now().Unix()
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":%d}`, now-60, now+480, appID)

	signingInput := base64URLEncode([]byte(header)) + "." + base64URLEncode([]byte(payload))

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := signer.SignDigest(ctx, digest[:])
	if err != nil {
		return fmt.Errorf("KMS signing failed: %w", err)
	}

	jwt := signingInput + "." + base64URLEncode(signature)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(githubBaseURL, "/")+"/app", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "import-github-app-key")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API error (HTTP %d): %s", resp.StatusCode, body)
	}

	var result struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if result.ID != appID {
		return fmt.Errorf("app ID mismatch: expected %d, got %d", appID, result.ID)
	}

	fmt.Fprintf(stdout, "Authentication successful: %s (ID: %d)\n", result.Name, result.ID)
	return nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
