use aes_kw::{KeyInit, KwpAes192, KwpAes256};
use hex_literal::hex;
use import_github_app_key::crypto::{encrypt_key_material, pem_to_pkcs8_der};
use rand::rngs::OsRng;
use rsa::{
    Oaep, RsaPrivateKey, pkcs1,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, PrivateKeyInfo, der::Encode},
    traits::PublicKeyParts,
};
use secrecy::ExposeSecret;
use sha2::Sha256;
use std::{fs, path::Path};

#[test]
fn both_pem_formats_preserve_the_same_rsa_key() {
    let pkcs1 = pem_to_pkcs8_der(Path::new("testdata/pkcs1.pem")).unwrap();
    let pkcs8 = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    assert!(pkcs1.expose_secret() == pkcs8.expose_secret());
    let parsed = RsaPrivateKey::from_pkcs8_der(pkcs8.expose_secret()).unwrap();
    assert_eq!(parsed.n().bits(), 2048);
    parsed.validate().unwrap();
    let debug = format!("{pkcs8:?}");
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!debug.contains("48, 130"));
}

#[test]
fn rejects_missing_malformed_oversized_and_unsupported_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    assert!(pem_to_pkcs8_der(&path).is_err());
    assert!(pem_to_pkcs8_der(dir.path()).is_err());
    for data in [
        Vec::new(),
        b"not a PEM file".to_vec(),
        vec![b'x'; 64 * 1024 + 1],
        b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".to_vec(),
        b"-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----\n".to_vec(),
    ] {
        fs::write(&path, data).unwrap();
        assert!(pem_to_pkcs8_der(&path).is_err());
    }
}

#[test]
fn rejects_non_rsa_and_wrong_size_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    let key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let der = key.to_pkcs8_der().unwrap();
    let pem =
        pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, der.as_bytes())
            .unwrap();
    fs::write(&path, pem).unwrap();
    assert!(
        pem_to_pkcs8_der(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("unexpected RSA key size: 1024")
    );
    let mut info = PrivateKeyInfo::new(pkcs1::ALGORITHM_ID, &[0]);
    info.algorithm.oid = rsa::pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let pem = pem_rfc7468::encode_string(
        "PRIVATE KEY",
        pem_rfc7468::LineEnding::LF,
        &info.to_der().unwrap(),
    )
    .unwrap();
    fs::write(&path, pem).unwrap();
    assert!(
        pem_to_pkcs8_der(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("not an RSA private key")
    );
}

#[test]
fn rsa_oaep_and_aes_kwp_round_trip_the_entire_private_key() {
    let der = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    let wrapping = RsaPrivateKey::from_pkcs8_der(der.expose_secret()).unwrap();
    let public = wrapping.to_public_key().to_public_key_der().unwrap();
    let wrapped = encrypt_key_material(der.expose_secret(), public.as_bytes()).unwrap();
    let aes_key = wrapping
        .decrypt(Oaep::new::<Sha256>(), &wrapped[..wrapping.size()])
        .unwrap();
    assert_eq!(aes_key.len(), 32);
    let kwp = KwpAes256::new_from_slice(&aes_key).unwrap();
    let mut unwrapped = vec![0; wrapped.len()];
    let plain = kwp
        .unwrap_key(&wrapped[wrapping.size()..], &mut unwrapped)
        .unwrap();
    assert!(plain == der.expose_secret());
    assert!(encrypt_key_material(der.expose_secret(), b"invalid public key").is_err());
    assert!(encrypt_key_material(&[], public.as_bytes()).is_err());
}

#[test]
fn rejects_corrupt_crt_parameters_before_import() {
    let source = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    let info = PrivateKeyInfo::try_from(source.expose_secret().as_slice()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    for field in 0..3 {
        let mut encoded = pkcs1::RsaPrivateKey::try_from(info.private_key).unwrap();
        let invalid = pkcs1::UintRef::new(&[1]).unwrap();
        match field {
            0 => encoded.exponent1 = invalid,
            1 => encoded.exponent2 = invalid,
            _ => encoded.coefficient = invalid,
        }
        let inner = encoded.to_der().unwrap();
        let der = PrivateKeyInfo::new(pkcs1::ALGORITHM_ID, &inner)
            .to_der()
            .unwrap();
        let pem =
            pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, &der).unwrap();
        fs::write(&path, pem).unwrap();
        assert!(
            pem_to_pkcs8_der(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("CRT")
        );
    }
}

#[test]
fn rejects_corrupt_private_components() {
    let source = pem_to_pkcs8_der(Path::new("testdata/pkcs8.pem")).unwrap();
    let info = PrivateKeyInfo::try_from(source.expose_secret().as_slice()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.pem");
    for field in 0..3 {
        let mut encoded = pkcs1::RsaPrivateKey::try_from(info.private_key).unwrap();
        let invalid = pkcs1::UintRef::new(&[1]).unwrap();
        match field {
            0 => encoded.private_exponent = invalid,
            1 => encoded.prime1 = invalid,
            _ => encoded.prime2 = invalid,
        }
        let pem = pem_rfc7468::encode_string(
            "RSA PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            &encoded.to_der().unwrap(),
        )
        .unwrap();
        fs::write(&path, pem).unwrap();
        assert!(pem_to_pkcs8_der(&path).is_err());
    }
}

#[test]
fn rfc5649_known_answer_vectors() {
    let key = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let kwp = KwpAes192::new_from_slice(&key).unwrap();
    for (plaintext, expected) in [
        (
            hex!("c37b7e6492584340bed12207808941155068f738").to_vec(),
            hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a").to_vec(),
        ),
        (
            hex!("466f7250617369").to_vec(),
            hex!("afbeb0f07dfbf5419200f2ccb50bb24f").to_vec(),
        ),
    ] {
        let mut output = vec![0; expected.len()];
        assert_eq!(kwp.wrap_key(&plaintext, &mut output).unwrap(), expected);
    }
}

#[test]
fn secret_types_have_drop_zeroization() {
    fn assert_zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroizes::<RsaPrivateKey>();
    assert_zeroizes::<KwpAes256>();
}
