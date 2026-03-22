//! Tests for parser

use fido_mds3_attestation_ca::error::*;
use fido_mds3_attestation_ca::parser::*;

#[test]
fn test_base64_decode_jwt_part_valid() -> Result<(), Box<dyn std::error::Error>> {
    // {"test": true} in URL-Safe No Pad
    let input = "eyJ0ZXN0IjogdHJ1ZX0";

    let result = base64_decode_jwt_part(input);
    assert!(result.is_ok());

    let decoded = String::from_utf8(result?)?;

    assert_eq!(decoded, r#"{"test": true}"#);
    Ok(())
}

#[test]
fn test_base64_decode_standard_with_padding() -> Result<(), Box<dyn std::error::Error>> {
    // "test" encoded in standard base64 is "dGVzdA=="
    let input = "dGVzdA==";

    let result = base64_decode_standard(input);
    assert!(result.is_ok());

    let decoded = result?;
    assert_eq!(decoded, b"test");

    Ok(())
}

#[test]
fn test_base64_decode_invalid() {
    let input = "!!!invalid!!!";
    // Both should fail on non-base64 characters
    assert!(base64_decode_jwt_part(input).is_err());
    assert!(base64_decode_standard(input).is_err());
}

#[test]
fn test_sha256_fingerprint() {
    use sha2::{Digest, Sha256};

    let data = b"test data";
    let fp = sha256_fingerprint(data);

    // 1. Check length (SHA-256 hex is always 64 characters)
    assert_eq!(fp.len(), 64);

    // 2. Check if it's valid hex
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

    // 3. Verify against a fresh calculation to ensure the function logic is sound
    let mut hasher = Sha256::new();
    hasher.update(data);
    let expected = hex::encode(hasher.finalize());

    assert_eq!(
        fp, expected,
        "Fingerprint mismatch! Expected {expected}, got {fp}"
    );
}

#[test]
fn test_pem_encode() {
    let der = b"test der data";
    let pem = pem_encode(der);
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("dGVzdCBkZXIgZGF0YQ==")); // "test der data" in b64
    assert!(pem.ends_with("-----END CERTIFICATE-----"));
}

#[test]
fn test_parse_blob_invalid_jwt() {
    // Test with 3 parts but garbage data
    let result = parse_blob("part1.part2.part3");
    assert!(result.is_err());
}

#[test]
fn test_parse_blob_wrong_parts() {
    let result = parse_blob("onlyonepart");
    assert!(matches!(
        result,
        Err(FidoMds3AttestationCaError::InvalidJwtError(_))
    ));

    let result_two = parse_blob("header.payload");
    assert!(matches!(
        result_two,
        Err(FidoMds3AttestationCaError::InvalidJwtError(_))
    ));
}

#[test]
fn test_extract_ca_entry_with_no_metadata() {
    let raw_json = serde_json::json!({
        "aaguid": "test-guid",
        "statusReports": []
    });

    let entries = extract_ca_entries(&raw_json);

    // The function should return exactly one placeholder entry
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];

    // Should still return an entry, but with "No cert" markers.
    assert_eq!(entry.aaguid, Some("test-guid".to_string()));
    assert_eq!(entry.certificate_pem, "No attestation root certificate");
}
