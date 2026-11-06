use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait DigestSigner: Send + Sync {
    async fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>>;
}

pub struct ImportedKey {
    pub signer: Box<dyn DigestSigner>,
    pub reference: String,
}

#[async_trait]
pub trait KeyImportProvider: Send + Sync {
    async fn wrapping_public_key_der(&mut self) -> Result<Vec<u8>>;
    async fn import_key_material(&self, encrypted: Vec<u8>) -> Result<ImportedKey>;
}
