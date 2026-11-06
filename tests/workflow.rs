mod common;

use anyhow::{Result, bail};
use async_trait::async_trait;
use import_github_app_key::{
    provider::{DigestSigner, ImportedKey, KeyImportProvider},
    workflow::{RunConfig, run},
};
use serde_json::json;
use std::{fs, io::Cursor, path::PathBuf};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

struct Signer {
    fail: bool,
}
#[async_trait]
impl DigestSigner for Signer {
    async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if self.fail {
            bail!("signing denied");
        }
        Ok(common::sign(digest))
    }
}

#[derive(Default)]
struct Provider {
    fail_prepare: bool,
    fail_import: bool,
    fail_sign: bool,
    replace_pem: Option<PathBuf>,
}
#[async_trait]
impl KeyImportProvider for Provider {
    async fn wrapping_public_key_der(&mut self) -> Result<Vec<u8>> {
        if self.fail_prepare {
            bail!("wrapping denied");
        }
        Ok(common::wrapping_der())
    }
    async fn import_key_material(&self, encrypted: Vec<u8>) -> Result<ImportedKey> {
        if self.fail_import {
            bail!("import denied");
        }
        common::assert_imported_key(&encrypted);
        if let Some(path) = &self.replace_pem {
            fs::write(path, "replacement file")?;
        }
        Ok(ImportedKey {
            signer: Box::new(Signer {
                fail: self.fail_sign,
            }),
            reference: "key-id".to_owned(),
        })
    }
}

fn config(dir: &tempfile::TempDir) -> RunConfig {
    let pem_file = dir.path().join("key.pem");
    fs::copy("testdata/pkcs1.pem", &pem_file).unwrap();
    RunConfig {
        pem_file,
        github_url: "http://unused.invalid".into(),
        app_id: None,
        delete_pem: false,
        dry_run: false,
    }
}

#[tokio::test]
async fn successful_import_verifies_jwt_before_deleting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/app"))
        .respond_with(|request: &Request| {
            common::assert_jwt(request.headers["authorization"].to_str().unwrap(), 12345);
            ResponseTemplate::new(200).set_body_json(json!({"id":12345,"name":"test-app"}))
        })
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.github_url = format!("{}/api/v3/", server.uri());
    cfg.app_id = Some(12345);
    cfg.delete_pem = true;
    let mut output = Vec::new();
    run(
        &mut Provider::default(),
        &common::http_client(),
        &mut Cursor::new(""),
        &mut output,
        &cfg,
    )
    .await
    .unwrap();
    assert!(!cfg.pem_file.exists());
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Authentication successful"));
    assert!(!output.contains("[y/N]"));
    assert!(!output.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn deletion_requires_a_positive_answer() {
    for (answer, deleted) in [
        ("y\n", true),
        (" Y \n", true),
        ("n\n", false),
        ("\n", false),
        ("", false),
        ("yes\n", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir);
        run(
            &mut Provider::default(),
            &common::http_client(),
            &mut Cursor::new(answer),
            &mut Vec::new(),
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(!cfg.pem_file.exists(), deleted);
    }
}

#[tokio::test]
async fn refuses_to_delete_a_file_changed_during_import() {
    for delete_pem in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.delete_pem = delete_pem;
        let mut provider = Provider {
            replace_pem: Some(cfg.pem_file.clone()),
            ..Default::default()
        };
        let error = run(
            &mut provider,
            &common::http_client(),
            &mut Cursor::new("y\n"),
            &mut Vec::new(),
            &cfg,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("changed after encryption"));
        assert_eq!(fs::read(&cfg.pem_file).unwrap(), b"replacement file");
    }
}

#[tokio::test]
async fn dry_run_never_imports_or_prompts_or_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.dry_run = true;
    // Any attempted import fails, making an unintended call observable.
    let mut provider = Provider {
        fail_import: true,
        ..Default::default()
    };
    let mut output = Vec::new();
    run(
        &mut provider,
        &common::http_client(),
        &mut Cursor::new("y\n"),
        &mut output,
        &cfg,
    )
    .await
    .unwrap();
    assert!(cfg.pem_file.exists());
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("Dry run complete")
    );
    for verify in [false, true] {
        cfg.delete_pem = !verify;
        cfg.app_id = verify.then_some(12345);
        assert!(
            run(
                &mut provider,
                &common::http_client(),
                &mut Cursor::new(""),
                &mut Vec::new(),
                &cfg
            )
            .await
            .is_err()
        );
        assert!(cfg.pem_file.exists());
    }
}

#[tokio::test]
async fn cloud_failures_never_delete_the_original_pem() {
    let server = MockServer::start().await;
    for mut provider in [
        Provider {
            fail_prepare: true,
            ..Default::default()
        },
        Provider {
            fail_import: true,
            ..Default::default()
        },
        Provider {
            fail_sign: true,
            ..Default::default()
        },
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.delete_pem = true;
        cfg.app_id = Some(12345);
        cfg.github_url = server.uri();
        assert!(
            run(
                &mut provider,
                &common::http_client(),
                &mut Cursor::new("y\n"),
                &mut Vec::new(),
                &cfg
            )
            .await
            .is_err()
        );
        assert!(cfg.pem_file.exists());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn github_failures_never_delete_the_original_pem() {
    for response in [
        ResponseTemplate::new(401).set_body_string("reflected-token-do-not-log"),
        ResponseTemplate::new(200).set_body_json(json!({"id":99999,"name":"wrong-app"})),
        ResponseTemplate::new(200).set_body_string("invalid json"),
        ResponseTemplate::new(200).set_body_string("x".repeat(1024 * 1024 + 1)),
        ResponseTemplate::new(302).insert_header("Location", "https://example.invalid/"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.github_url = server.uri();
        cfg.app_id = Some(12345);
        cfg.delete_pem = true;
        let error = run(
            &mut Provider::default(),
            &common::http_client(),
            &mut Cursor::new("y\n"),
            &mut Vec::new(),
            &cfg,
        )
        .await
        .unwrap_err();
        assert!(!format!("{error:#}").contains("reflected-token-do-not-log"));
        assert!(cfg.pem_file.exists());
    }
}
