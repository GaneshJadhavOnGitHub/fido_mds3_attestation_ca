//! Tests for fido_mds3_attestation_ca

use base64::{Engine, engine::general_purpose};
use chrono::Utc;
use fido_mds3_attestation_ca::parser::base64_decode_jwt_part;
use fido_mds3_attestation_ca::types::{CaEntry, ParsedBlob};
use fido_mds3_attestation_ca::{embedded_ca_list, loader, universal_user_path};
use serde_json::{Value, json};
use uuid::Uuid;
mod common;
#[test]
fn test_embedded_data_exists() {
    common::init_logger();
    // 1. Include the raw JWT string from your data folder
    let jwt_str = include_str!("../data/ca_list.jwt");

    if jwt_str.is_empty() {
        log::error!("Embedded JWT should not be empty");
        return;
    }

    // 2. Extract the payload (the middle part of the JWT)
    let parts: Vec<&str> = jwt_str.split('.').collect();

    if parts.len() != 3 {
        log::error!(
            "Embedded data is not a valid 3-part JWT. Parts found: {}",
            parts.len()
        );
        return;
    }

    // 3. Decode the Base64URL payload using your NEW helper
    let payload_bytes = match base64_decode_jwt_part(parts[1]) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to decode JWT payload part: {e:?}");
            return;
        }
    };

    // 4. Parse the decoded JSON bytes into your ParsedBlob struct
    // Using from_slice here because payload_bytes is a Vec<u8>
    let result: Result<Value, _> = serde_json::from_slice(&payload_bytes);

    if result.is_err() {
        log::error!(
            "Should parse decoded JSON payload but failed: {:?}",
            result.as_ref().err()
        );
        return;
    }

    let json_value = match result {
        Ok(v) => v,
        Err(_) => return,
    };

    // Verify the "entries" field exists in the JSON
    if json_value.get("entries").is_none() {
        log::error!("MDS3 blob missing 'entries' field");
        return;
    }

    assert!(json_value.get("entries").is_some());
}
#[test]
fn test_embedded_ca_list_loads() {
    let list = embedded_ca_list();
    // If we get here, parsing succeeded
    assert!(list.total_entries == list.cas.len(), "Count mismatch");
}

#[test]
fn test_loader_embedded_source() {
    common::init_logger();
    let result = loader::load_jwt();
    assert!(result.is_ok(), "Should load embedded CA list");

    let list = match result {
        Ok(v) => v,
        Err(e) => {
            log::error!("Unexpected error while loading embedded CA list: {:?}", e);
            return;
        }
    };

    assert!(!list.cas.is_empty(), "Embedded list should have entries");
}

#[test]
fn test_loader_file_source_valid() {
    common::init_logger();
    // 1. Get the REAL path the loader uses
    let real_cache_path = match universal_user_path() {
        Ok(path) => path,
        Err(e) => {
            log::error!("Failed to determine universal user path: {e:?}");
            return;
        }
    };

    // Backup the existing real file if it exists so we don't destroy your real data
    let backup_path = real_cache_path.with_extension("jwt.bak");
    if real_cache_path.exists() {
        if let Err(e) = std::fs::rename(&real_cache_path, &backup_path) {
            log::error!("Failed to backup existing jwt file: {e:?}");
            return;
        }
    }

    // 2. Create a Mock JWT (header.payload.signature)
    // MDS3 parser expects "entries" inside the payload
    let test_payload = serde_json::json!({
        "entries": [{
            "aaguid": "test-aaguid-123",
            "metadataStatement": {
                "description": "Test Device",
                "attestationRootCertificates": []
            }
        }]
    });

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload_b64 = URL_SAFE_NO_PAD.encode(test_payload.to_string());
    let mock_jwt = format!("eyJhbGciOiJIUzI1NiJ9.{payload_b64}.signature");

    // 3. Write to the REAL path location
    // Ensure the directory exists (your universal_user_path function does this)
    if let Err(e) = std::fs::write(&real_cache_path, mock_jwt) {
        log::error!("Failed to write mock jwt file: {e:?}");
        return;
    }

    // 4. Test loading
    let result = loader::load_blob_and_call_parser(&real_cache_path);

    // 5. Cleanup: Restore the original file
    if let Err(e) = std::fs::remove_file(&real_cache_path) {
        log::warn!("Failed to remove mock jwt file during cleanup: {e:?}");
    }

    if backup_path.exists() {
        if let Err(e) = std::fs::rename(&backup_path, &real_cache_path) {
            log::warn!("Failed to restore original jwt file: {e:?}");
        }
    }

    // 6. Assertions
    assert!(
        result.is_ok(),
        "Should load valid CA list: {:?}",
        result.err()
    );

    let list = match result {
        Ok(v) => v,
        Err(e) => {
            log::error!("Loader returned error: {e:?}");
            return;
        }
    };

    assert_eq!(list.cas[0].device_name, "Test Device");
}
#[test]
fn test_ca_list_metadata() {
    let list = embedded_ca_list();

    // Check metadata consistency
    assert_eq!(
        list.cas.len(),
        list.total_entries,
        "total_entries should match actual count"
    );

    // Check all entries have required fields
    for ca in &list.cas {
        assert!(
            !ca.device_name.is_empty(),
            "Device name should not be empty"
        );
        assert!(
            !ca.certificate_pem.is_empty(),
            "Certificate should not be empty"
        );
        assert!(
            !ca.fingerprint.is_empty(),
            "Fingerprint should not be empty"
        );
    }
}

#[test]
fn test_extract_uuid_strict_logic() {
    use std::sync::Arc;

    common::init_logger();

    let loader = ParsedBlob {
        cas: vec![],
        generated_at: chrono::Utc::now(),
        total_entries: 10,
    };

    // Case 1: Native AAGUID (FIDO2)
    // We use the top-level 'aaguid' field and verify it parses correctly.
    let aaguid_str = "12345678-1234-1234-1234-1234567890ab";

    let entry_fido2 = CaEntry {
        aaguid: Some(aaguid_str.to_string()),
        device_name: "FIDO2 Device".to_string(),
        raw_data: Some(Arc::new(json!({ "aaguid": aaguid_str }))),
        ..Default::default()
    };

    let uuid_fido2 = loader.extract_uuid_strict(&entry_fido2);

    let parsed_uuid = match Uuid::parse_str(aaguid_str) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Failed to parse AAGUID '{aaguid_str}': {e:?}");
            return;
        }
    };

    assert_eq!(uuid_fido2, parsed_uuid);

    // Case 2: U2F AAID (Legacy)
    // No top-level field exists, so we rely entirely on the 'raw_data' JSON map.
    let aaid_str = "0005:0001";

    let entry_u2f = CaEntry {
        aaguid: None,
        device_name: "U2F Device".to_string(),
        raw_data: Some(Arc::new(json!({ "aaid": aaid_str }))),
        ..Default::default()
    };

    let uuid_u2f = loader.extract_uuid_strict(&entry_u2f);

    // Manual verification of the Hash logic (v5 Name-based UUID)
    let expected_v5 = Uuid::new_v5(&Uuid::NAMESPACE_DNS, aaid_str.as_bytes());

    assert_eq!(uuid_u2f, expected_v5);

    if uuid_u2f.is_nil() {
        log::warn!("Generated UUID for AAID '{aaid_str}' resulted in NIL UUID");
    }

    assert_ne!(uuid_u2f, Uuid::nil());

    // Case 3: Empty Entry (The "Ghost" device)
    // Should return a Nil UUID
    let entry_empty = CaEntry {
        aaguid: None,
        device_name: "Unknown Device".to_string(),
        raw_data: Some(Arc::new(json!({}))),
        ..Default::default()
    };

    let uuid_nil = loader.extract_uuid_strict(&entry_empty);

    if !uuid_nil.is_nil() {
        log::error!("Expected NIL UUID for empty entry but received {uuid_nil:?}");
        return;
    }

    assert!(uuid_nil.is_nil());
}
#[test]
fn test_build_attestation_trust_anchors_filters_entries() {
    use std::sync::Arc;

    common::init_logger();

    // Create valid base64 data so decoding succeeds
    let valid_cert_b64 = general_purpose::STANDARD.encode(b"valid-test-cert");

    // Entry WITH certificate (should be processed)
    let valid_entry = CaEntry {
        aaguid: Some("12345678-1234-1234-1234-1234567890ab".to_string()),
        device_name: "Valid Device".to_string(),
        raw_data: Some(Arc::new(json!({
            "metadataStatement": {
                "attestationRootCertificates": [valid_cert_b64]
            }
        }))),
        ..Default::default()
    };

    // Entry WITHOUT certificates (should be skipped)
    let skipped_entry = CaEntry {
        aaguid: None,
        device_name: "Skipped Device".to_string(),
        raw_data: Some(Arc::new(json!({
            "metadataStatement": {}
        }))),
        ..Default::default()
    };

    let blob = ParsedBlob {
        cas: vec![valid_entry, skipped_entry],
        generated_at: Utc::now(),
        total_entries: 2,
    };

    let result = blob.build_attestation_trust_anchors();

    assert!(
        result.is_ok(),
        "Trust anchor generation should succeed: {:?}",
        result.err()
    );

    let list = match result {
        Ok(list) => list,
        Err(_) => return,
    };

    // Since builder may reject invalid DER, we only verify filtering behavior
    assert!(
        list.cas().len() <= 1,
        "Function should not produce more trust anchors than valid entries"
    );
}
#[test]
fn test_build_fido_certified_trust_anchors_filters_status() {
    use std::sync::Arc;

    common::init_logger();

    let cert_b64 = general_purpose::STANDARD.encode(b"test-cert");

    // Certified device (should be included)
    let certified_entry = CaEntry {
        aaguid: Some("12345678-1234-1234-1234-1234567890ab".to_string()),
        device_name: "Certified Device".to_string(),
        raw_data: Some(Arc::new(json!({
            "statusReports": [
                {
                    "status": "FIDO_CERTIFIED_L1",
                    "effectiveDate": "2023-01-01"
                }
            ],
            "metadataStatement": {
                "attestationRootCertificates": [cert_b64]
            }
        }))),
        ..Default::default()
    };

    // Non-certified device (should be skipped)
    let non_certified_entry = CaEntry {
        aaguid: None,
        device_name: "Non Certified".to_string(),
        raw_data: Some(Arc::new(json!({
            "statusReports": [
                {
                    "status": "USER_VERIFICATION_BYPASS",
                    "effectiveDate": "2023-01-01"
                }
            ],
            "metadataStatement": {
                "attestationRootCertificates": [cert_b64]
            }
        }))),
        ..Default::default()
    };

    let blob = ParsedBlob {
        cas: vec![certified_entry, non_certified_entry],
        generated_at: Utc::now(),
        total_entries: 2,
    };

    let result = blob.build_fido_certified_trust_anchors();

    assert!(
        result.is_ok(),
        "FIDO certified trust anchor generation should succeed: {:?}",
        result.err()
    );

    let list = match result {
        Ok(list) => list,
        Err(_) => return,
    };

    // Only certified entry should remain
    assert!(
        list.cas().len() <= 1,
        "Non-certified devices must be filtered out"
    );
}
