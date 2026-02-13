// CLI tool to import a GitHub App private key into AWS KMS.
//
// Prerequisites:
//   - The KMS key must be created in advance (e.g. via Terraform)
//     with KeySpec: RSA_2048, KeyUsage: SIGN_VERIFY, Origin: EXTERNAL
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var version = "dev"

// CLI defines the command-line interface parsed by Kong.
type CLI struct {
	Version   kong.VersionFlag `short:"V" help:"Print version and exit."`
	KeyID     string           `arg:"" required:"" help:"KMS key ID or ARN."`
	PEMFile   string           `arg:"" required:"" help:"Path to the GitHub App private key PEM file." type:"existingfile"`
	Verify    *int             `short:"v" optional:"" help:"GitHub App ID. If specified, validates the imported key by calling the GitHub API."`
	Delete    bool             `short:"d" optional:"" help:"Delete the PEM file after a successful import without prompting."`
	DryRun    bool             `optional:"" help:"Validate the PEM file and KMS wrapping parameters without importing."`
	GitHubURL string           `optional:"" default:"https://api.github.com" help:"GitHub API base URL. Set this for GitHub Enterprise Server (e.g. https://github.example.com/api/v3)."`
}

// Validate implements kong.Validatable.
func (c *CLI) Validate() error {
	if c.Verify != nil && *c.Verify <= 0 {
		return fmt.Errorf("--verify requires a positive App ID, got %d", *c.Verify)
	}
	if c.DryRun && (c.Delete || c.Verify != nil) {
		return fmt.Errorf("--dry-run cannot be combined with --delete or --verify")
	}
	return nil
}

func main() {
	var cli CLI
	kong.Parse(&cli,
		kong.Name("import-github-app-key"),
		kong.Description("Import a GitHub App private key into a cloud KMS."),
		kong.Vars{"version": version},
	)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load AWS config: %v\n", err)
		os.Exit(1)
	}

	client := kms.NewFromConfig(cfg)
	httpClient := &http.Client{Timeout: 30 * time.Second}

	err = run(ctx, client, httpClient, os.Stdin, os.Stdout, runConfig{
		GitHubBaseURL: cli.GitHubURL,
		KeyID:         cli.KeyID,
		PEMFile:       cli.PEMFile,
		AppID:         cli.Verify,
		DeletePEM:     cli.Delete,
		DryRun:        cli.DryRun,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
