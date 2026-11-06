use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::{
    Client,
    primitives::Blob,
    types::{
        AlgorithmSpec, ExpirationModelType, MessageType, SigningAlgorithmSpec, WrappingKeySpec,
    },
};

use crate::provider::{DigestSigner, ImportedKey, KeyImportProvider};

pub struct AwsProvider {
    client: Client,
    key_id: String,
    import_token: Option<Blob>,
}

impl AwsProvider {
    pub fn new(client: Client, key_id: String) -> Self {
        Self {
            client,
            key_id,
            import_token: None,
        }
    }
}

#[async_trait]
impl KeyImportProvider for AwsProvider {
    async fn wrapping_public_key_der(&mut self) -> Result<Vec<u8>> {
        self.import_token = None;
        let output = self
            .client
            .get_parameters_for_import()
            .key_id(&self.key_id)
            .wrapping_algorithm(AlgorithmSpec::RsaAesKeyWrapSha256)
            .wrapping_key_spec(WrappingKeySpec::Rsa4096)
            .send()
            .await
            .context("failed to get AWS wrapping parameters")?;
        let key = output
            .public_key
            .filter(|key| !key.as_ref().is_empty())
            .context("AWS KMS returned an empty wrapping public key")?;
        let token = output
            .import_token
            .filter(|token| !token.as_ref().is_empty())
            .context("AWS KMS returned an empty import token")?;
        self.import_token = Some(token);
        Ok(key.into_inner())
    }

    async fn import_key_material(&self, encrypted: Vec<u8>) -> Result<ImportedKey> {
        let token = self
            .import_token
            .as_ref()
            .context("AWS import token is missing; fetch wrapping parameters first")?;
        self.client
            .import_key_material()
            .key_id(&self.key_id)
            .encrypted_key_material(Blob::new(encrypted))
            .import_token(token.clone())
            .expiration_model(ExpirationModelType::KeyMaterialDoesNotExpire)
            .send()
            .await
            .context("AWS KMS import failed")?;
        Ok(ImportedKey {
            signer: Box::new(AwsSigner {
                client: self.client.clone(),
                key_id: self.key_id.clone(),
            }),
            reference: self.key_id.clone(),
        })
    }
}

pub struct AwsSigner {
    pub client: Client,
    pub key_id: String,
}

#[async_trait]
impl DigestSigner for AwsSigner {
    async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .context("AWS KMS signing failed")?;
        let signature = output
            .signature
            .filter(|signature| !signature.as_ref().is_empty())
            .context("AWS KMS returned an empty signature")?;
        Ok(signature.into_inner())
    }
}
