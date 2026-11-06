mod common;

use aws_sdk_kms::{
    Client as AwsClient,
    config::{BehaviorVersion, Credentials, Region, retry::RetryConfig},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use google_cloud_kms_v1::client::KeyManagementService;
use import_github_app_key::{
    aws::{AwsProvider, AwsSigner},
    gcp::{GcpProvider, GcpSigner},
    provider::{DigestSigner, KeyImportProvider},
    workflow::{RunConfig, run},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{header, method, path},
};

const KEY: &str = "projects/p/locations/global/keyRings/r/cryptoKeys/k";
const JOB: &str = "projects/p/locations/global/keyRings/r/importJobs/j";
const VERSION: &str = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

fn aws(server: &MockServer) -> AwsProvider {
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("test", "test", None, None, "test"))
        .region(Region::new("us-east-1"))
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .endpoint_url(server.uri())
        .build();
    AwsProvider::new(AwsClient::from_conf(config), "key-id".into())
}

async fn gcp_client(server: &MockServer) -> KeyManagementService {
    KeyManagementService::builder()
        .with_endpoint(server.uri())
        .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
        .build()
        .await
        .unwrap()
}

async fn gcp(server: &MockServer) -> GcpProvider {
    GcpProvider::new(gcp_client(server).await, KEY.into(), JOB.into())
        .with_polling(Duration::from_millis(1), Duration::from_millis(100))
}

async fn verify_and_delete(provider: &mut dyn KeyImportProvider, server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/app"))
        .respond_with(|request: &Request| {
            common::assert_jwt(request.headers["authorization"].to_str().unwrap(), 12345);
            ResponseTemplate::new(200).set_body_json(json!({"id":12345,"name":"test-app"}))
        })
        .expect(1)
        .mount(server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("key.pem");
    fs::copy("testdata/pkcs1.pem", &pem).unwrap();
    run(
        provider,
        &common::http_client(),
        &mut Cursor::new(""),
        &mut Vec::new(),
        &RunConfig {
            pem_file: pem.clone(),
            github_url: server.uri(),
            app_id: Some(12345),
            delete_pem: true,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert!(!pem.exists());
}

#[tokio::test]
async fn aws_real_sdk_imports_the_original_key_and_signs_a_valid_jwt() {
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "TrentService.GetParametersForImport"))
        .respond_with(|r: &Request| {
            let body: Value = r.body_json().unwrap();
            assert_eq!(body["KeyId"], "key-id");
            assert_eq!(body["WrappingAlgorithm"], "RSA_AES_KEY_WRAP_SHA_256");
            assert_eq!(body["WrappingKeySpec"], "RSA_4096");
            ResponseTemplate::new(200).set_body_json(json!({"PublicKey":STANDARD.encode(common::wrapping_der()),"ImportToken":STANDARD.encode("token")}))
        }).expect(1).mount(&server).await;
    Mock::given(header("x-amz-target", "TrentService.ImportKeyMaterial"))
        .respond_with(|r: &Request| {
            let body: Value = r.body_json().unwrap();
            assert_eq!(body["KeyId"], "key-id");
            assert_eq!(body["ExpirationModel"], "KEY_MATERIAL_DOES_NOT_EXPIRE");
            assert_eq!(common::decode(&body["ImportToken"]), b"token");
            common::assert_imported_key(&common::decode(&body["EncryptedKeyMaterial"]));
            ResponseTemplate::new(200).set_body_json(json!({}))
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-amz-target", "TrentService.Sign"))
        .respond_with(|r: &Request| {
            let body: Value = r.body_json().unwrap();
            assert_eq!(body["KeyId"], "key-id");
            assert_eq!(body["MessageType"], "DIGEST");
            assert_eq!(body["SigningAlgorithm"], "RSASSA_PKCS1_V1_5_SHA_256");
            ResponseTemplate::new(200).set_body_json(json!({"Signature":STANDARD.encode(common::sign(&common::decode(&body["Message"])))}))
        }).expect(1).mount(&server).await;
    verify_and_delete(&mut aws(&server), &server).await;
}

#[tokio::test]
async fn aws_rejects_missing_import_parameters() {
    let server = MockServer::start().await;
    assert!(aws(&server).import_key_material(vec![]).await.is_err());
    for response in [
        json!({}),
        json!({"PublicKey":"","ImportToken":"dA=="}),
        json!({"PublicKey":"cHVi","ImportToken":""}),
        json!({"PublicKey":"cHVi"}),
    ] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(aws(&server).wrapping_public_key_der().await.is_err());
    }
}

#[tokio::test]
async fn aws_rejects_missing_or_empty_signatures() {
    let server = MockServer::start().await;
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(Credentials::new("test", "test", None, None, "test"))
        .region(Region::new("us-east-1"))
        .endpoint_url(server.uri())
        .build();
    let signer = AwsSigner {
        client: AwsClient::from_conf(config),
        key_id: "key-id".into(),
    };
    for response in [json!({}), json!({"Signature":""})] {
        server.reset().await;
        Mock::given(header("x-amz-target", "TrentService.Sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            signer
                .sign_digest(&[42; 32])
                .await
                .unwrap_err()
                .to_string()
                .contains("empty signature")
        );
    }
}

#[tokio::test]
async fn gcp_real_sdk_imports_polls_and_verifies_with_crc32c() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path(format!("/v1/{JOB}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":JOB,"state":"ACTIVE","importMethod":"RSA_OAEP_4096_SHA256_AES_256","publicKey":{"pem":common::wrapping_pem()}})))
        .expect(1).mount(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{KEY}/cryptoKeyVersions:import")))
        .respond_with(|r: &Request| {
            let body: Value = r.body_json().unwrap();
            // The Rust SDK requests enum-encoding=int; 5 is RSA_SIGN_PKCS1_2048_SHA256.
            assert_eq!(body["algorithm"], 5);
            assert_eq!(body["importJob"], JOB);
            common::assert_imported_key(&common::decode(&body["wrappedKey"]));
            ResponseTemplate::new(200)
                .set_body_json(json!({"name":VERSION,"state":"PENDING_IMPORT"}))
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/{VERSION}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"name":VERSION,"state":"ENABLED"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path(format!("/v1/{VERSION}:asymmetricSign")))
        .respond_with(|r: &Request| {
            let body: Value = r.body_json().unwrap();
            let digest = common::decode(&body["digest"]["sha256"]);
            assert_eq!(body["digestCrc32c"], crc32c::crc32c(&digest).to_string());
            let signature = common::sign(&digest);
            ResponseTemplate::new(200).set_body_json(json!({"name":VERSION,"signature":STANDARD.encode(&signature),"signatureCrc32c":crc32c::crc32c(&signature).to_string(),"verifiedDigestCrc32c":true}))
        }).expect(1).mount(&server).await;
    verify_and_delete(&mut gcp(&server).await, &server).await;
}

#[tokio::test]
async fn gcp_rejects_inactive_or_unsupported_import_jobs() {
    let server = MockServer::start().await;
    for (response, expected_error) in [
        (
            json!({"name":"wrong-job","state":"ACTIVE","importMethod":"RSA_OAEP_4096_SHA256_AES_256","publicKey":{"pem":common::wrapping_pem()}}),
            "different import job",
        ),
        (
            json!({"name":JOB,"state":"PENDING_GENERATION","importMethod":"RSA_OAEP_4096_SHA256_AES_256"}),
            "not active",
        ),
        (
            json!({"name":JOB,"state":"ACTIVE","importMethod":"RSA_OAEP_4096_SHA1_AES_256"}),
            "unsupported GCP import method",
        ),
        (
            json!({"name":JOB,"state":"ACTIVE","importMethod":"RSA_OAEP_4096_SHA256_AES_256"}),
            "empty wrapping public key",
        ),
        (
            json!({"name":JOB,"state":"ACTIVE","importMethod":"RSA_OAEP_4096_SHA256_AES_256","publicKey":{"pem":"invalid"}}),
            "failed to decode",
        ),
    ] {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let error = gcp(&server)
            .await
            .wrapping_public_key_der()
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error:#}");
    }
}

#[tokio::test]
async fn gcp_rejects_bad_signature_integrity() {
    let server = MockServer::start().await;
    let checksum = crc32c::crc32c(b"signature");
    for (name, verified, signature, crc, expected_error) in [
        (
            VERSION,
            false,
            "signature",
            Some(checksum),
            "request digest checksum was not verified",
        ),
        (
            "wrong-version",
            true,
            "signature",
            Some(checksum),
            "key version mismatch",
        ),
        (
            VERSION,
            true,
            "signature",
            Some(checksum ^ 1),
            "signature checksum mismatch",
        ),
        (
            VERSION,
            true,
            "signature",
            None,
            "signature checksum mismatch",
        ),
        (VERSION, true, "", Some(0), "empty signature"),
    ] {
        server.reset().await;
        let mut body = json!({"name":name,"verifiedDigestCrc32c":verified,"signature":STANDARD.encode(signature)});
        if let Some(crc) = crc {
            body["signatureCrc32c"] = json!(crc.to_string());
        }
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let signer = GcpSigner {
            client: gcp_client(&server).await,
            key_version: VERSION.into(),
        };
        let error = signer.sign_digest(&[42; 32]).await.unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error:#}");
    }
}

#[tokio::test]
async fn gcp_rejects_failed_missing_and_unexpected_versions() {
    let server = MockServer::start().await;
    for response in [
        json!({"name":VERSION,"state":"IMPORT_FAILED","importFailureReason":"bad key"}),
        json!({"state":"ENABLED"}),
        json!({"name":VERSION,"state":"DESTROYED"}),
        json!({"name":format!("{KEY}-other/cryptoKeyVersions/1"),"state":"ENABLED"}),
        json!({"name":format!("{KEY}/cryptoKeyVersions/"),"state":"ENABLED"}),
    ] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            gcp(&server)
                .await
                .import_key_material(vec![1, 2, 3])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn gcp_rejects_a_different_version_when_polling() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name":VERSION,"state":"PENDING_IMPORT"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"name":format!("{KEY}/cryptoKeyVersions/2"),"state":"ENABLED"}),
            ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = gcp(&server)
        .await
        .import_key_material(vec![1, 2, 3])
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("different CryptoKeyVersion"));
}

#[tokio::test]
async fn gcp_pending_import_has_a_bounded_wait() {
    let server = MockServer::start().await;
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name":VERSION,"state":"PENDING_IMPORT"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::Relaxed);
            ResponseTemplate::new(200)
                .set_body_json(json!({"name":VERSION,"state":"PENDING_IMPORT"}))
        })
        .mount(&server)
        .await;
    let error = gcp(&server)
        .await
        .import_key_material(vec![1, 2, 3])
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("timed out"));
    assert!(polls.load(Ordering::Relaxed) > 0);
}
