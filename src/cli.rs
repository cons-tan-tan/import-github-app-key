use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Parser, ValueEnum};

use crate::github::app_url;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Provider {
    #[default]
    Aws,
    Gcp,
}

#[derive(Debug, Parser)]
#[command(version = option_env!("APP_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")), about)]
pub struct Cli {
    /// KMS provider to import into.
    #[arg(long, value_enum, default_value = "aws")]
    pub provider: Provider,
    /// AWS KMS key ID/ARN, or GCP CryptoKey resource name.
    pub key_id: String,
    /// Path to the GitHub App private key PEM file.
    pub pem_file: PathBuf,
    /// GitHub App ID. Validate the imported key against the GitHub API.
    #[arg(short = 'v', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub verify: Option<u64>,
    /// Delete the PEM file without prompting after import and any requested verification.
    #[arg(short = 'd', long)]
    pub delete: bool,
    /// Validate the PEM file and KMS wrapping parameters without importing.
    #[arg(long, conflicts_with_all = ["delete", "verify"])]
    pub dry_run: bool,
    /// GitHub HTTPS API base URL. Supports GitHub Enterprise Server.
    #[arg(long, default_value = "https://api.github.com")]
    pub github_url: String,
    /// GCP ImportJob resource name. Required with --provider=gcp.
    #[arg(long)]
    pub gcp_import_job: Option<String>,
}

impl Cli {
    pub fn validate(&self) -> Result<()> {
        if self.verify.is_some() {
            ensure!(
                app_url(&self.github_url)?.scheme() == "https",
                "--github-url must use HTTPS"
            );
        }
        match self.provider {
            Provider::Aws => ensure!(
                self.gcp_import_job.is_none(),
                "--gcp-import-job requires --provider=gcp"
            ),
            Provider::Gcp => ensure!(
                self.gcp_import_job.as_ref().is_some_and(|s| !s.is_empty()),
                "--gcp-import-job is required when --provider=gcp"
            ),
        }
        ensure!(
            self.pem_file.is_file(),
            "PEM file does not exist or is not a regular file"
        );
        Ok(())
    }
}
