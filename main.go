// CLI tool to import a GitHub App private key into a cloud KMS.
//
// Prerequisites:
//   - The KMS key must be created in advance for external key material import
//     and RSA SHA-256 signing.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	gcpkms "cloud.google.com/go/kms/apiv1"
	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var version = "dev"

// CLI defines the command-line interface parsed by Kong.
type CLI struct {
	Version      kong.VersionFlag `short:"V" help:"Print version and exit."`
	Provider     string           `optional:"" default:"aws" enum:"aws,gcp" help:"KMS provider to import into."`
	KeyID        string           `arg:"" required:"" help:"KMS key ID/ARN for AWS, or CryptoKey resource name for GCP."`
	PEMFile      string           `arg:"" required:"" help:"Path to the GitHub App private key PEM file." type:"existingfile"`
	Verify       *int             `short:"v" optional:"" help:"GitHub App ID. If specified, validates the imported key by calling the GitHub API."`
	Delete       bool             `short:"d" optional:"" help:"Delete the PEM file after a successful import without prompting."`
	DryRun       bool             `optional:"" help:"Validate the PEM file and KMS wrapping parameters without importing."`
	GitHubURL    string           `name:"github-url" optional:"" default:"https://api.github.com" help:"GitHub API base URL. Set this for GitHub Enterprise Server (e.g. https://github.example.com/api/v3)."`
	GCPImportJob string           `name:"gcp-import-job" optional:"" help:"GCP ImportJob resource name. Required when --provider=gcp."`
}

// Validate implements kong.Validatable.
func (c *CLI) Validate() error {
	provider := strings.ToLower(c.Provider)
	switch provider {
	case "", "aws":
		if c.GCPImportJob != "" {
			return fmt.Errorf("--gcp-import-job requires --provider=gcp")
		}
	case "gcp":
		if c.GCPImportJob == "" {
			return fmt.Errorf("--gcp-import-job is required when --provider=gcp")
		}
	default:
		return fmt.Errorf("--provider must be aws or gcp, got %q", c.Provider)
	}
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
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var provider keyImportProvider
	switch strings.ToLower(cli.Provider) {
	case "aws":
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to load AWS config: %v\n", err)
			os.Exit(1)
		}
		provider = newAWSProvider(kms.NewFromConfig(cfg), cli.KeyID)
	case "gcp":
		client, err := gcpkms.NewKeyManagementClient(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create GCP KMS client: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()
		provider = newGCPProvider(client, cli.KeyID, cli.GCPImportJob)
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported provider: %s\n", cli.Provider)
		os.Exit(1)
	}

	err := run(ctx, provider, httpClient, os.Stdin, os.Stdout, runConfig{
		GitHubBaseURL: cli.GitHubURL,
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
