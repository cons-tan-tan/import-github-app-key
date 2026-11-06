use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::provider::DigestSigner;

pub fn app_url(base_url: &str) -> Result<Url> {
    let mut url = Url::parse(base_url).map_err(|_| anyhow!("invalid GitHub API URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "GitHub API URL must be an HTTP(S) URL with a host"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "GitHub API URL must not contain credentials, a query, or a fragment"
    );
    url.set_path(&format!("{}/app", url.path().trim_end_matches('/')));
    Ok(url)
}

pub async fn validate_with_github(
    signer: &dyn DigestSigner,
    client: &Client,
    output: &mut dyn Write,
    base_url: &str,
    app_id: u64,
) -> Result<()> {
    let url = app_url(base_url)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"iat":{},"exp":{},"iss":{}}}"#,
        now.saturating_sub(60),
        now + 480,
        app_id
    ));
    let signing_input = format!("{header}.{payload}");
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature = signer
        .sign_digest(&digest)
        .await
        .context("KMS signing failed")?;
    let jwt = Zeroizing::new(format!(
        "Bearer {signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ));
    let mut authorization = HeaderValue::from_str(&jwt)?;
    authorization.set_sensitive(true);
    let mut response = client
        .get(url)
        .header(AUTHORIZATION, authorization)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "import-github-app-key")
        .send()
        .await
        .context("GitHub API request failed")?;
    // Do not echo remote error bodies, which could reflect credentials.
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "GitHub API error (HTTP {})",
        response.status().as_u16()
    );
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read GitHub response")?
    {
        ensure!(
            body.len() + chunk.len() <= 1024 * 1024,
            "GitHub response exceeds 1 MiB"
        );
        body.extend_from_slice(&chunk);
    }
    #[derive(Deserialize)]
    struct App {
        id: u64,
        name: String,
    }
    // Serde diagnostics can include response values, including reflected credentials.
    let app: App =
        serde_json::from_slice(&body).map_err(|_| anyhow!("failed to parse GitHub response"))?;
    ensure!(
        app.id == app_id,
        "app ID mismatch: expected {app_id}, got {}",
        app.id
    );
    writeln!(
        output,
        "Authentication successful: {} (ID: {})",
        app.name.escape_debug(),
        app.id
    )?;
    Ok(())
}
