#![allow(dead_code)]

use aes_kw::{KeyInit, KwpAes256};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use import_github_app_key::crypto::pem_to_pkcs8_der;
use rsa::{
    Oaep, Pkcs1v15Sign, RsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

// The repository fixtures are throwaway keys, never production credentials.
pub fn key() -> RsaPrivateKey {
    let der = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    RsaPrivateKey::from_pkcs8_der(der.expose_secret()).unwrap()
}

pub fn wrapping_der() -> Vec<u8> {
    key()
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

pub fn wrapping_pem() -> String {
    pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &wrapping_der()).unwrap()
}

pub fn assert_imported_key(encrypted: &[u8]) {
    let key = key();
    let aes = key
        .decrypt(Oaep::new::<Sha256>(), &encrypted[..key.size()])
        .unwrap();
    assert_eq!(aes.len(), 32);
    let kwp = KwpAes256::new_from_slice(&aes).unwrap();
    let mut plain = vec![0; encrypted.len()];
    let der = kwp
        .unwrap_key(&encrypted[key.size()..], &mut plain)
        .unwrap();
    let expected = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    assert!(der == expected.expose_secret());
}

pub fn sign(digest: &[u8]) -> Vec<u8> {
    key().sign(Pkcs1v15Sign::new::<Sha256>(), digest).unwrap()
}

pub fn assert_jwt(authorization: &str, app_id: u64) {
    let token = authorization.strip_prefix("Bearer ").unwrap();
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], app_id);
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        540
    );
    let digest = Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
    key()
        .to_public_key()
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .unwrap();
}

pub fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
