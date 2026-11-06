use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use google_cloud_kms_v1::{
    client::KeyManagementService,
    model::{CryptoKeyVersion, Digest, crypto_key_version, import_job},
};

use crate::provider::{DigestSigner, ImportedKey, KeyImportProvider};

pub struct GcpProvider {
    client: KeyManagementService,
    crypto_key: String,
    import_job: String,
    poll_interval: Duration,
    poll_timeout: Duration,
}

impl GcpProvider {
    pub fn new(client: KeyManagementService, crypto_key: String, import_job: String) -> Self {
        Self {
            client,
            crypto_key,
            import_job,
            poll_interval: Duration::from_secs(2),
            poll_timeout: Duration::from_secs(300),
        }
    }

    pub fn with_polling(mut self, interval: Duration, timeout: Duration) -> Self {
        self.poll_interval = interval;
        self.poll_timeout = timeout;
        self
    }

    async fn wait_for_enabled(&self, mut version: CryptoKeyVersion) -> Result<CryptoKeyVersion> {
        let name = version.name.clone();
        tokio::time::timeout(self.poll_timeout, async {
            loop {
                ensure!(
                    version.name == name,
                    "GCP returned a different CryptoKeyVersion while polling"
                );
                match version.state {
                    crypto_key_version::CryptoKeyVersionState::Enabled => return Ok(version),
                    crypto_key_version::CryptoKeyVersionState::ImportFailed => {
                        bail!("GCP key import failed: {}", version.import_failure_reason)
                    }
                    crypto_key_version::CryptoKeyVersionState::PendingImport
                    | crypto_key_version::CryptoKeyVersionState::Unspecified => {}
                    _ => bail!(
                        "unexpected CryptoKeyVersion state after import: {:?}",
                        version.state
                    ),
                }
                tokio::time::sleep(self.poll_interval).await;
                version = self
                    .client
                    .get_crypto_key_version()
                    .set_name(&name)
                    .send()
                    .await
                    .context("failed to get CryptoKeyVersion state")?;
            }
        })
        .await
        .context("timed out waiting for GCP key version to become ENABLED")?
    }
}

#[async_trait]
impl KeyImportProvider for GcpProvider {
    async fn wrapping_public_key_der(&mut self) -> Result<Vec<u8>> {
        let job = self
            .client
            .get_import_job()
            .set_name(&self.import_job)
            .send()
            .await
            .context("failed to get GCP import job")?;
        ensure!(
            job.name == self.import_job,
            "GCP returned a different import job"
        );
        ensure!(
            job.state == import_job::ImportJobState::Active,
            "GCP import job is not active"
        );
        ensure!(
            matches!(
                job.import_method,
                import_job::ImportMethod::RsaOaep3072Sha256Aes256
                    | import_job::ImportMethod::RsaOaep4096Sha256Aes256
            ),
            "unsupported GCP import method: expected SHA-256 RSA-OAEP with AES-256 wrapping"
        );
        let pem = job
            .public_key
            .context("GCP import job returned an empty wrapping public key")?
            .pem;
        ensure!(
            !pem.is_empty(),
            "GCP import job returned an empty wrapping public key"
        );
        let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())
            .context("failed to decode GCP wrapping public key")?;
        ensure!(
            label == "PUBLIC KEY",
            "unexpected GCP wrapping public key PEM type"
        );
        Ok(der)
    }

    async fn import_key_material(&self, encrypted: Vec<u8>) -> Result<ImportedKey> {
        let version = self
            .client
            .import_crypto_key_version()
            .set_parent(&self.crypto_key)
            .set_import_job(&self.import_job)
            .set_algorithm(crypto_key_version::CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256)
            .set_wrapped_key(encrypted)
            .send()
            .await
            .context("GCP KMS import failed")?;
        ensure!(
            !version.name.is_empty(),
            "GCP import returned an empty CryptoKeyVersion name"
        );
        ensure!(
            version
                .name
                .rsplit_once("/cryptoKeyVersions/")
                .is_some_and(|(parent, id)| parent == self.crypto_key
                    && !id.is_empty()
                    && !id.contains('/')),
            "GCP import returned a CryptoKeyVersion outside the requested key"
        );
        let version = self.wait_for_enabled(version).await?;
        Ok(ImportedKey {
            signer: Box::new(GcpSigner {
                client: self.client.clone(),
                key_version: version.name.clone(),
            }),
            reference: version.name,
        })
    }
}

pub struct GcpSigner {
    pub client: KeyManagementService,
    pub key_version: String,
}

#[async_trait]
impl DigestSigner for GcpSigner {
    async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .client
            .asymmetric_sign()
            .set_name(&self.key_version)
            .set_digest(Digest::new().set_sha256(digest.to_vec()))
            .set_digest_crc32c(i64::from(crc32c::crc32c(digest)))
            .send()
            .await
            .context("GCP KMS signing failed")?;
        ensure!(
            response.name == self.key_version,
            "AsymmetricSign response key version mismatch"
        );
        ensure!(
            response.verified_digest_crc32c,
            "AsymmetricSign request digest checksum was not verified"
        );
        ensure!(
            response.signature_crc32c == Some(i64::from(crc32c::crc32c(&response.signature))),
            "AsymmetricSign response signature checksum mismatch"
        );
        ensure!(
            !response.signature.is_empty(),
            "GCP KMS returned an empty signature"
        );
        Ok(response.signature.to_vec())
    }
}
