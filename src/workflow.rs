use std::{
    io::{BufRead, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use reqwest::Client;

use crate::{
    crypto::{encrypt_pem_file, pem_file_digest},
    github::validate_with_github,
    provider::KeyImportProvider,
};

pub struct RunConfig {
    pub pem_file: PathBuf,
    pub github_url: String,
    pub app_id: Option<u64>,
    pub delete_pem: bool,
    pub dry_run: bool,
}

pub async fn run(
    provider: &mut dyn KeyImportProvider,
    client: &Client,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    config: &RunConfig,
) -> Result<()> {
    ensure!(
        !config.dry_run || (!config.delete_pem && config.app_id.is_none()),
        "--dry-run cannot be combined with --delete or --verify"
    );
    writeln!(output, "Fetching KMS wrapping parameters...")?;
    let wrapping_key = provider
        .wrapping_public_key_der()
        .await
        .context("failed to get wrapping parameters")?;
    writeln!(
        output,
        "Converting PEM to PKCS#8 DER and encrypting private key..."
    )?;
    let (encrypted, pem_digest) = encrypt_pem_file(&config.pem_file, &wrapping_key)
        .context("private key encryption failed")?;
    if config.dry_run {
        writeln!(output, "Dry run complete (skipping import)")?;
        return Ok(());
    }
    writeln!(output, "Importing into KMS...")?;
    let imported = provider
        .import_key_material(encrypted)
        .await
        .context("KMS import failed")?;
    writeln!(output, "KMS import complete: {}", imported.reference)?;
    if let Some(app_id) = config.app_id {
        writeln!(output, "\nValidating with GitHub API...")?;
        validate_with_github(
            imported.signer.as_ref(),
            client,
            output,
            &config.github_url,
            app_id,
        )
        .await
        .context("validation failed")?;
    }
    // Never move deletion before verification: GitHub App keys cannot be
    // downloaded again if the import or verification fails.
    let should_delete = if config.delete_pem {
        true
    } else {
        write!(output, "\nDelete PEM file? [y/N]: ")?;
        output.flush()?;
        let mut answer = String::new();
        input
            .read_line(&mut answer)
            .context("failed to read deletion confirmation")?;
        answer.trim().eq_ignore_ascii_case("y")
    };
    if should_delete {
        ensure!(
            pem_file_digest(&config.pem_file).context("failed to recheck PEM before deletion")?
                == pem_digest,
            "PEM file changed after encryption; refusing to delete it"
        );
        // shortcut: compare/delete assumes exclusive directory access; use an atomic strategy for shared paths.
        std::fs::remove_file(&config.pem_file).context("failed to delete PEM file")?;
        writeln!(output, "Deleted: {}", config.pem_file.display())?;
    }
    writeln!(output, "Done")?;
    Ok(())
}
