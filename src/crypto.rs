use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::Path,
};

use aes_kw::{KeyInit, KwpAes256};
use anyhow::{Context, Result, bail, ensure};
use rand::{RngCore, rngs::OsRng};
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey, pkcs1,
    pkcs8::{DecodePublicKey, PrivateKeyInfo, der::Encode},
    traits::PrivateKeyParts,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// An RSA-2048 PEM is normally under 2 KiB. A fixed bound avoids reallocating
// plaintext buffers and also bounds the work performed on untrusted input.
const MAX_PEM_BYTES: usize = 64 * 1024;
pub type SecretBytes = SecretBox<Vec<u8>>;

fn secret_buffer(len: usize) -> SecretBytes {
    SecretBox::new(Box::new(vec![0; len]))
}

pub fn pem_to_pkcs8_der(path: &Path) -> Result<SecretBytes> {
    decode_private_key(read_pem(path)?.expose_secret())
}

fn read_pem(path: &Path) -> Result<SecretBytes> {
    let mut file = File::open(path).context("failed to read PEM file")?;
    ensure!(
        file.metadata()
            .context("failed to inspect PEM file")?
            .is_file(),
        "PEM input must be a regular file"
    );
    let mut pem = secret_buffer(MAX_PEM_BYTES + 1);
    let mut len = 0;
    while len < pem.expose_secret().len() {
        let read = match file.read(&mut pem.expose_secret_mut()[len..]) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("failed to read PEM file"),
        };
        if read == 0 {
            break;
        }
        len += read;
    }
    ensure!(len <= MAX_PEM_BYTES, "PEM file exceeds the 64 KiB limit");
    pem.expose_secret_mut().truncate(len);
    Ok(pem)
}

pub(crate) fn pem_file_digest(path: &Path) -> Result<[u8; 32]> {
    Ok(Sha256::digest(read_pem(path)?.expose_secret()).into())
}

fn decode_private_key(pem: &[u8]) -> Result<SecretBytes> {
    let mut der = secret_buffer(pem.len());
    let (label, decoded) =
        pem_rfc7468::decode(pem, der.expose_secret_mut()).context("failed to decode PEM")?;
    let len = decoded.len();
    // Parse borrowed ASN.1 first. In particular, do not serialize the parsed RSA
    // key back through temporary unguarded PKCS#1 buffers.
    let info = match label {
        "RSA PRIVATE KEY" => PrivateKeyInfo::new(pkcs1::ALGORITHM_ID, decoded),
        "PRIVATE KEY" => PrivateKeyInfo::try_from(decoded).context("invalid PKCS#8 private key")?,
        _ => bail!("unsupported PEM type: expected RSA PRIVATE KEY or PRIVATE KEY"),
    };
    ensure!(
        info.algorithm.oid == pkcs1::ALGORITHM_OID,
        "not an RSA private key"
    );
    let encoded =
        pkcs1::RsaPrivateKey::try_from(info.private_key).context("invalid PKCS#1 private key")?;
    let modulus = encoded.modulus.as_bytes();
    let bits = modulus.len() * 8 - modulus.first().map_or(0, |b| b.leading_zeros() as usize);
    ensure!(
        bits == 2048,
        "unexpected RSA key size: {bits} (GitHub App keys must be RSA-2048)"
    );

    // RsaPrivateKey zeroizes its private components and precomputed values on
    // Drop; dependency-internal arithmetic temporaries are not covered.
    let key = RsaPrivateKey::try_from(info.clone()).context("failed to parse RSA private key")?;
    // The decoder validates the key but recomputes CRT values; check the original DER too.
    let dp = Zeroizing::new(key.dp().context("missing RSA CRT exponent")?.to_bytes_be());
    let dq = Zeroizing::new(key.dq().context("missing RSA CRT exponent")?.to_bytes_be());
    let coefficient = Zeroizing::new(
        key.qinv()
            .context("missing RSA CRT coefficient")?
            .to_bytes_be()
            .1,
    );
    ensure!(
        dp.as_slice() == encoded.exponent1.as_bytes()
            && dq.as_slice() == encoded.exponent2.as_bytes()
            && coefficient.as_slice() == encoded.coefficient.as_bytes(),
        "invalid RSA CRT parameters"
    );
    drop(key);

    if label == "PRIVATE KEY" {
        der.expose_secret_mut().truncate(len);
        return Ok(der);
    }
    let mut pkcs8 = secret_buffer(usize::try_from(info.encoded_len()?)?);
    info.encode_to_slice(pkcs8.expose_secret_mut())
        .context("failed to encode PKCS#8 private key")?;
    Ok(pkcs8)
}

pub fn encrypt_key_material(
    private_key_der: &[u8],
    wrapping_public_key_der: &[u8],
) -> Result<Vec<u8>> {
    ensure!(!private_key_der.is_empty(), "private key must not be empty");
    let public_key = RsaPublicKey::from_public_key_der(wrapping_public_key_der)
        .context("failed to parse RSA wrapping public key")?;
    let mut aes_key = secret_buffer(32);
    OsRng
        .try_fill_bytes(aes_key.expose_secret_mut())
        .context("failed to generate AES key")?;
    let cipher = KwpAes256::new_from_slice(aes_key.expose_secret())
        .map_err(|_| anyhow::anyhow!("invalid AES key length"))?;

    // The output buffer temporarily contains plaintext while wrapping. Guard it
    // even on failure. The zeroize feature also erases the AES key schedule.
    let mut wrapped = Zeroizing::new(vec![0; private_key_der.len().div_ceil(8) * 8 + 8]);
    cipher
        .wrap_key(private_key_der, &mut wrapped)
        .map_err(|_| anyhow::anyhow!("AES key wrap failed"))?;
    let mut encrypted = public_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), aes_key.expose_secret())
        .context("RSA-OAEP encryption failed")?;
    encrypted.extend_from_slice(&wrapped);
    Ok(encrypted)
}

// Return ciphertext and a digest only, so network waits cannot extend secret lifetimes.
pub fn encrypt_pem_file(
    path: &Path,
    wrapping_public_key_der: &[u8],
) -> Result<(Vec<u8>, [u8; 32])> {
    let pem = read_pem(path)?;
    let digest = Sha256::digest(pem.expose_secret()).into();
    let der = decode_private_key(pem.expose_secret())?;
    drop(pem);
    Ok((
        encrypt_key_material(der.expose_secret(), wrapping_public_key_der)?,
        digest,
    ))
}
