use aws_sdk_kms::{
    Client,
    config::{BehaviorVersion, Region, retry::RetryConfig},
    types::{KeySpec, KeyState, KeyUsageType, OriginType},
};
use import_github_app_key::{
    aws::{AwsProvider, AwsSigner},
    crypto::{encrypt_pem_file, pem_to_pkcs8_der},
    provider::{DigestSigner, KeyImportProvider},
    workflow::{RunConfig, run},
};
use rsa::{
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use serde_json::json;
use sha2::{Digest, Sha256};
use smithy_server_runtime::{EmbeddedEmulator, MultiServiceRouter};
use std::{fs, io::Cursor, path::PathBuf, sync::Arc};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header_exists, method, path},
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn fixture_public_key() -> RsaPublicKey {
    let der = pem_to_pkcs8_der(&fixture("pkcs8.pem")).unwrap();
    RsaPrivateKey::from_pkcs8_der(der.expose_secret())
        .unwrap()
        .to_public_key()
}

fn client() -> Client {
    let engine = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(true);
    router.register_service(kms_emulator::EmulatedService::new(engine));
    let emulator = EmbeddedEmulator::from_router(router);
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .http_client(emulator.http_client())
        .credentials_provider(emulator.aws_credentials_provider())
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .build();
    Client::from_conf(config)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn external_key(client: &Client) -> String {
    let response = client
        .create_key()
        .origin(OriginType::External)
        .key_spec(KeySpec::Rsa2048)
        .key_usage(KeyUsageType::SignVerify)
        .send()
        .await
        .unwrap();
    let key = response.key_metadata().unwrap();
    assert_eq!(key.key_state(), Some(&KeyState::PendingImport));
    key.key_id().to_owned()
}

async fn key_state(client: &Client, key_id: &str) -> KeyState {
    client
        .describe_key()
        .key_id(key_id)
        .send()
        .await
        .unwrap()
        .key_metadata()
        .unwrap()
        .key_state()
        .unwrap()
        .clone()
}

fn config(dir: &tempfile::TempDir) -> RunConfig {
    let pem_file = dir.path().join("key.pem");
    fs::copy(fixture("pkcs1.pem"), &pem_file).unwrap();
    RunConfig {
        pem_file,
        github_url: "http://127.0.0.1:1".into(),
        app_id: None,
        delete_pem: false,
        dry_run: false,
    }
}

#[tokio::test]
async fn rsa4096_wrapped_fixtures_import_and_sign_sha256_digests() {
    let client = client();
    let public = fixture_public_key();
    let digest = Sha256::digest(b"kms-integration-test");
    for name in ["pkcs1.pem", "pkcs8.pem"] {
        let key_id = external_key(&client).await;
        let mut provider = AwsProvider::new(client.clone(), key_id.clone());
        let signer = AwsSigner {
            client: client.clone(),
            key_id: key_id.clone(),
        };
        assert!(signer.sign_digest(&digest).await.is_err());
        let wrapping = provider.wrapping_public_key_der().await.unwrap();
        assert_eq!(
            RsaPublicKey::from_public_key_der(&wrapping)
                .unwrap()
                .n()
                .bits(),
            4096
        );
        let (encrypted, _) = encrypt_pem_file(&fixture(name), &wrapping).unwrap();
        let imported = provider.import_key_material(encrypted).await.unwrap();
        assert_eq!(key_state(&client, &key_id).await, KeyState::Enabled);
        let response = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .unwrap();
        let imported_public =
            RsaPublicKey::from_public_key_der(response.public_key().unwrap().as_ref()).unwrap();
        assert_eq!(imported_public, public);
        let signature = imported.signer.sign_digest(&digest).await.unwrap();
        public
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .unwrap();
    }
}

#[tokio::test]
async fn dry_run_preserves_pending_import_and_pem() {
    let client = client();
    let key_id = external_key(&client).await;
    let mut provider = AwsProvider::new(client.clone(), key_id.clone());
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.dry_run = true;
    run(
        &mut provider,
        &http_client(),
        &mut Cursor::new(""),
        &mut Vec::new(),
        &cfg,
    )
    .await
    .unwrap();
    assert!(cfg.pem_file.exists());
    assert_eq!(key_state(&client, &key_id).await, KeyState::PendingImport);
}

#[tokio::test]
async fn github_verification_controls_pem_deletion() {
    let client = client();
    for succeeds in [true, false] {
        let key_id = external_key(&client).await;
        let mut provider = AwsProvider::new(client.clone(), key_id.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/app"))
            .and(header_exists("authorization"))
            .respond_with(
                ResponseTemplate::new(if succeeds { 200 } else { 401 })
                    .set_body_json(json!({"id":12345,"name":"test-app"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        cfg.github_url = server.uri();
        cfg.app_id = Some(12345);
        cfg.delete_pem = true;
        let result = run(
            &mut provider,
            &http_client(),
            &mut Cursor::new(""),
            &mut Vec::new(),
            &cfg,
        )
        .await;
        assert_eq!(result.is_ok(), succeeds, "{result:?}");
        assert_eq!(cfg.pem_file.exists(), !succeeds);
        assert_eq!(key_state(&client, &key_id).await, KeyState::Enabled);
    }
}

#[tokio::test]
async fn nonexistent_kms_key_preserves_pem() {
    let mut provider = AwsProvider::new(client(), "00000000-0000-0000-0000-000000000000".into());
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.delete_pem = true;
    let result = run(
        &mut provider,
        &http_client(),
        &mut Cursor::new(""),
        &mut Vec::new(),
        &cfg,
    )
    .await;
    assert!(result.is_err());
    assert!(cfg.pem_file.exists());
}
