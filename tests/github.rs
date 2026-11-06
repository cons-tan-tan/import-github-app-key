mod common;

use anyhow::Result;
use async_trait::async_trait;
use import_github_app_key::{
    github::{app_url, validate_with_github},
    provider::DigestSigner,
};
use serde_json::json;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

struct Signer;

#[async_trait]
impl DigestSigner for Signer {
    async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        Ok(common::sign(digest))
    }
}

struct UnusedSigner;

#[async_trait]
impl DigestSigner for UnusedSigner {
    async fn sign_digest(&self, _: &[u8]) -> Result<Vec<u8>> {
        panic!("an invalid URL must be rejected before signing")
    }
}

#[tokio::test]
async fn invalid_urls_are_rejected_before_signing_without_echoing_credentials() {
    for url in [
        "invalid",
        "file:///tmp/token",
        "https://user:secret-token@example.com/api/v3",
        "https://example.com/api/v3?token=secret-token",
        "https://example.com/api/v3#secret-token",
    ] {
        let error = validate_with_github(
            &UnusedSigner,
            &common::http_client(),
            &mut Vec::new(),
            url,
            12345,
        )
        .await
        .unwrap_err();
        assert!(!format!("{error:#}").contains("secret-token"));
    }
    assert_eq!(
        app_url("https://example.com/api/v3/").unwrap().as_str(),
        "https://example.com/api/v3/app"
    );
}

#[tokio::test]
async fn malformed_success_responses_cannot_echo_credentials_in_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "reflected-token-do-not-log", "name": "test-app"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let error = validate_with_github(
        &Signer,
        &common::http_client(),
        &mut Vec::new(),
        &server.uri(),
        12345,
    )
    .await
    .unwrap_err();
    assert!(!format!("{error:#}").contains("reflected-token-do-not-log"));
}

#[tokio::test]
async fn app_names_cannot_inject_terminal_controls() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 12345, "name": "テスト\n\u{1b}[2J"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut output = Vec::new();
    validate_with_github(
        &Signer,
        &common::http_client(),
        &mut output,
        &server.uri(),
        12345,
    )
    .await
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("テスト\\n\\u{1b}[2J"));
    assert!(!output.contains('\u{1b}'));
    assert_eq!(output.lines().count(), 1);
}
