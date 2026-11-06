use std::{io, process::ExitCode, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use import_github_app_key::{
    aws::AwsProvider,
    cli::{Cli, Provider},
    gcp::GcpProvider,
    provider::KeyImportProvider,
    workflow::{RunConfig, run},
};

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<()> {
    cli.validate()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut provider: Box<dyn KeyImportProvider> = match cli.provider {
        Provider::Aws => {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            Box::new(AwsProvider::new(
                aws_sdk_kms::Client::new(&config),
                cli.key_id,
            ))
        }
        Provider::Gcp => {
            let client = google_cloud_kms_v1::client::KeyManagementService::builder()
                .build()
                .await
                .context("failed to create GCP KMS client")?;
            Box::new(GcpProvider::new(
                client,
                cli.key_id,
                cli.gcp_import_job.unwrap_or_default(),
            ))
        }
    };
    run(
        provider.as_mut(),
        &client,
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        &RunConfig {
            pem_file: cli.pem_file,
            github_url: cli.github_url,
            app_id: cli.verify,
            delete_pem: cli.delete,
            dry_run: cli.dry_run,
        },
    )
    .await
}
