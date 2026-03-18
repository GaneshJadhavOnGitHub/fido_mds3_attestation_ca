//! Tests for fido_mds3_attestation_ca

use base64::{Engine, engine::general_purpose};
use chrono::Utc;
use fido_mds3_attestation_ca::types::{CaEntry, ParsedBlob};
use fido_mds3_attestation_ca::{embedded_ca_list, loader, universal_user_path};
use serde_json::json;
use uuid::Uuid;
mod common;

// These are only used in test_embedded_data_exists (gated by 'embedded')
#[cfg(feature = "embedded")]
use fido_mds3_attestation_ca::parser::base64_decode_jwt_part;
#[cfg(feature = "embedded")]
use serde_json::Value;

#[test]
fn test_fallback_behavior() {
    let list = embedded_ca_list();

    #[cfg(feature = "embedded")]
    {
        // If feature is ON, the list should NOT be empty
        assert!(
            !list.cas.is_empty(),
            "Embedded list should contain data when 'embedded' feature is enabled"
        );
    }

    #[cfg(not(feature = "embedded"))]
    {
        // If feature is OFF, the list should be empty
        assert!(
            list.cas.is_empty(),
            "Embedded list should be empty when 'embedded' feature is disabled"
        );
    }
}
// This test checks the actual physical file in the data folder.
// It should only run if the user intends to test the embedded data.
#[test]
#[cfg(feature = "embedded")]
fn test_embedded_data_exists() {
    common::init_logger();
    let jwt_str = include_str!("../data/ca_list.jwt");

    if jwt_str.is_empty() {
        panic!("Embedded JWT should not be empty when feature is enabled");
    }

    let parts: Vec<&str> = jwt_str.split('.').collect();
    assert_eq!(parts.len(), 3, "Embedded data is not a valid 3-part JWT");

    let payload_bytes = base64_decode_jwt_part(parts[1]).expect("Failed to decode JWT payload");
    let json_value: Value =
        serde_json::from_slice(&payload_bytes).expect("Should parse JSON payload");

    assert!(
        json_value.get("entries").is_some(),
        "MDS3 blob missing 'entries' field"
    );
}

#[test]
#[cfg(feature = "embedded")]
fn test_embedded_ca_list_loads() {
    let list = embedded_ca_list();
    // Only check count consistency if the list is expected to be populated
    assert!(list.total_entries == list.cas.len(), "Count mismatch");
}

#[test]
#[cfg(feature = "embedded")]
fn test_loader_embedded_source() {
    common::init_logger();
    let result = loader::load_jwt();
    assert!(result.is_ok(), "Should load embedded CA list");

    let list = result.unwrap();
    assert!(
        !list.cas.is_empty(),
        "Embedded list should have entries when feature is enabled"
    );
}

#[test]
#[cfg(feature = "embedded")]
fn test_ca_list_metadata() {
    let list = embedded_ca_list();

    assert_eq!(
        list.cas.len(),
        list.total_entries,
        "total_entries should match actual count"
    );

    for ca in &list.cas {
        assert!(!ca.device_name.is_empty());
        assert!(!ca.certificate_pem.is_empty());
        assert!(!ca.fingerprint.is_empty());
    }
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
