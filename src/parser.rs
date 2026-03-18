//! Parser for FIDO MDS3 JWT blob to extract attestation CA certificates.
//!
//! This module contains the core parsing logic used to extract
//! **attestation certificate authorities (CAs)** from a
//! **FIDO Metadata Service (MDS) v3 JWT blob**.
//!
//! The FIDO Metadata Service publishes a signed JWT containing
//! metadata entries for authenticators. Each entry may contain
//! one or more **attestation root certificates** which are used
//! during `WebAuthn` attestation verification.
//!
//! This module performs the following tasks:
//!
//! 1. Splits the JWT into header, payload, and signature.
//! 2. Decodes the payload (Base64 URL-safe).
//! 3. Parses the JSON metadata structure.
//! 4. Extracts authenticator metadata entries.
//! 5. Extracts attestation root certificates.
//! 6. Converts them into [`CaEntry`] records.
//!
//! The parsed result is returned as a [`ParsedBlob`] structure,
//! which contains the extracted certificate authorities along
//! with metadata about the parsing process.
//!
//! # Output
//!
//! The extracted CA entries can later be converted into an
//! `AttestationCaList` for use in `WebAuthn` attestation validation.
//!
//! # Error Handling
//!
//! Errors during parsing are converted into
//! [`FidoMds3AttestationCaError`] variants and logged for debugging.
//!
//! # Notes
//!
//! - JWT payload decoding uses **URL-safe Base64 without padding**.
//! - Certificates inside metadata entries use **standard Base64**.
//! - Only the **first attestation root certificate** is currently used
//!   when multiple are present.
//!
//! # Security Consideration
//!
//! This module **parses** the metadata blob but does **not verify the JWT
//! signature** as it assumes that jwt blob is downloaded from official FIDO MDS website.
//! Signature verification should be performed before trusting
//! metadata in high-security environments.
use serde_json::Value;
use {
    super::error::FidoMds3AttestationCaError,
    super::types::{CaEntry, ParsedBlob},
};

/// Parse JWT blob and extract CA list
///
/// Parses a **FIDO MDS3 metadata JWT blob** and extracts attestation
/// certificate authorities from its entries.
///
/// The function performs the following operations:
///
/// 1. Splits the JWT into `header.payload.signature`.
/// 2. Decodes the payload using URL-safe Base64.
/// 3. Deserializes the payload JSON.
/// 4. Extracts the `entries` array.
/// 5. Converts each entry into a [`CaEntry`].
///
/// The resulting entries are returned inside a [`ParsedBlob`] structure.
///
/// # Arguments
///
/// * `jwt` - The raw FIDO MDS3 JWT blob as a string.
///
/// # Returns
///
/// * `Ok(ParsedBlob)` – Successfully parsed blob with extracted CA entries.
/// * `Err(FidoMds3AttestationCaError)` – If decoding or parsing fails.
///
/// # Errors
///
/// This function returns an error if:
///
/// - The JWT format is invalid (not 3 parts).
/// - Base64 decoding of the payload fails.
/// - The payload is not valid UTF-8.
/// - JSON deserialization fails.
/// - The `entries` field is missing from the payload.
///
/// # Logging
///
/// - `error` logs are emitted for parsing failures.
/// - `debug` logs report the number of metadata entries processed.
///
pub fn parse_blob(jwt: &str) -> Result<ParsedBlob, FidoMds3AttestationCaError> {
    // JWT: header.payload.signature
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        let err = FidoMds3AttestationCaError::InvalidJwtError(format!(
            "Expected 3 parts, got {}",
            parts.len()
        ));
        log::error!("Invalid Jwt: {err}");
        return Err(err);
    }

    // 1. Decode payload (JWT uses URL-Safe Base64 without padding)
    let payload_bytes = base64_decode_jwt_part(parts[1])
        .inspect_err(|e| log::error!("Decode error: {e}"))
        .map_err(FidoMds3AttestationCaError::Base64Error)?;

    let payload_json = String::from_utf8(payload_bytes)
        .inspect_err(|e| log::error!("Invalid UTF8: {e}"))
        .map_err(|_| FidoMds3AttestationCaError::InvalidUtf8Error)?;

    let mds: Value = serde_json::from_str(&payload_json)
        .inspect_err(|e| log::error!("Deserialization Error: {e}"))
        .map_err(FidoMds3AttestationCaError::JsonError)?;

    // 2. Extract entries array
    let entries = mds
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| FidoMds3AttestationCaError::MissingFieldError("entries".into()))
        .inspect_err(|e| log::error!("Validation failed: {e}"))?;

    log::debug!("Total entries in blob: {}", entries.len());

    //let cas: Vec<CaEntry> = entries.iter().map(extract_ca_entry).collect();
    let cas: Vec<CaEntry> = entries.iter().flat_map(extract_ca_entries).collect();

    log::debug!("Extracted: {}", cas.len());

    Ok(ParsedBlob {
        generated_at: chrono::Utc::now(),
        total_entries: cas.len(),
        cas,
    })
}
/// Extract one or more [`CaEntry`] records from a metadata entry.
///
/// A single **FIDO MDS3 metadata entry** may contain multiple
/// `attestationRootCertificates`. Each certificate represents a valid
/// **attestation trust anchor**, therefore this function produces
/// **one [`CaEntry`] per certificate**.
///
/// The function extracts:
///
/// - Authenticator identifier (`AAGUID` or `AAID`)
/// - Device description
/// - Attestation root certificate
/// - Certificate SHA-256 fingerprint
/// - Certificate validity period
/// - Attestation types
/// - Protocol family
///
/// Certificate processing includes:
///
/// 1. Base64 decoding of the certificate.
/// 2. SHA-256 fingerprint generation.
/// 3. Conversion to PEM format.
/// 4. Extraction of certificate validity timestamps using `x509-parser`.
///
/// If no certificate exists in the metadata entry, a **placeholder
/// [`CaEntry`]** is returned to maintain consistent downstream behavior.
///
/// # Arguments
///
/// * `entry` – A single JSON metadata entry from the FIDO Metadata Service blob.
///
/// # Returns
///
/// A `Vec<CaEntry>` where each element represents a **trust anchor**
/// extracted from the metadata entry.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
///
/// // Minimal example metadata entry
/// let entry = json!({
///     "aaguid": "12345678-1234-1234-1234-1234567890ab",
///     "metadataStatement": {
///         "description": "Example Authenticator",
///         "attestationRootCertificates": [
///             "MIIB...example_base64_certificate..."
///         ],
///         "attestationTypes": ["basic_full"],
///         "protocolFamily": "fido2"
///     }
/// });
///
/// let entries = fido_mds3_attestation_ca::parser::extract_ca_entries(&entry);
///
/// assert!(!entries.is_empty());
/// ```
/// # Performance
///
/// - The vector capacity is **preallocated** based on the number of
///   certificates to avoid reallocations.
/// - Metadata fields are **extracted once** and reused.
/// - The original JSON entry is stored using `Arc<Value>` so that
///   multiple [`CaEntry`] values can share the same metadata without
///   duplicating memory.
///
/// This significantly reduces memory usage when parsing the
/// **~9 MB FIDO Metadata Service blob**.
///
/// # Notes
///
/// - Certificates inside metadata entries are encoded using
///   **standard Base64**.
/// - Some authenticators publish **multiple root certificates**
///   due to certificate rotation or multiple attestation chains.
/// - The full metadata entry is preserved in `raw_data` for
///   debugging and auditing purposes.
pub fn extract_ca_entries(entry: &Value) -> Vec<CaEntry> {
    use std::sync::Arc;
    use x509_parser::prelude::*;

    let metadata = entry.get("metadataStatement");

    // Extract AAGUID or AAID (MDS3 may use either)
    let aaguid = entry
        .get("aaguid")
        .and_then(|v| v.as_str())
        .or_else(|| entry.get("aaid").and_then(|v| v.as_str()))
        .map(str::to_string);

    // Device description
    let device_name = metadata
        .and_then(|m| m.get("description"))
        .and_then(|d| d.as_str())
        .unwrap_or("Unknown Device")
        .to_string();

    // Certificate subject
    let subject = metadata
        .and_then(|m| m.get("attestationRootCertificateSubject"))
        .and_then(|s| s.as_str())
        .unwrap_or("Unknown")
        .to_string();

    // Supported attestation types
    let attestation_types: Vec<String> = metadata
        .and_then(|m| m.get("attestationTypes"))
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Protocol family (fido2, u2f, etc.)
    let protocol_family = metadata
        .and_then(|m| m.get("protocolFamily"))
        .and_then(|p| p.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Share raw JSON across entries to avoid cloning large structures
    let raw_data = Arc::new(entry.clone());

    // Retrieve attestation root certificates
    let certs = metadata
        .and_then(|m| m.get("attestationRootCertificates"))
        .and_then(|c| c.as_array());

    if let Some(certs) = certs {
        let mut results = Vec::with_capacity(certs.len());

        for cert_b64 in certs.iter().filter_map(|v| v.as_str()) {
            if let Ok(cert_der) = base64_decode_standard(cert_b64) {
                let fingerprint = sha256_fingerprint(&cert_der);
                let cert_pem = pem_encode(&cert_der);

                // Default validity timestamps
                let mut not_before = "1970-01-01T00:00:00Z".to_string();
                let mut not_after = "1970-01-01T00:00:00Z".to_string();

                // Parse certificate validity using x509-parser
                if let Ok((_, x509)) = X509Certificate::from_der(&cert_der) {
                    let validity = x509.validity();
                    not_before = format_x509_time(validity.not_before);
                    not_after = format_x509_time(validity.not_after);
                }

                results.push(CaEntry {
                    aaguid: aaguid.clone(),
                    device_name: device_name.clone(),
                    subject: subject.clone(),
                    certificate_pem: cert_pem,
                    fingerprint,
                    not_before,
                    not_after,
                    attestation_types: attestation_types.clone(),
                    protocol_family: protocol_family.clone(),
                    raw_data: Some(raw_data.clone()),
                });
            }
        }

        if !results.is_empty() {
            return results;
        }
    }

    // Fallback placeholder entry when no certificates exist
    vec![CaEntry {
        aaguid,
        device_name,
        subject,
        certificate_pem: "No attestation root certificate".to_string(),
        fingerprint: "no-cert".to_string(),
        not_before: "1970-01-01T00:00:00Z".to_string(),
        not_after: "1970-01-01T00:00:00Z".to_string(),
        attestation_types,
        protocol_family,
        raw_data: Some(raw_data),
    }]
}
/// Helper to convert `x509_parser` `ASN1Time` to ISO 8601 String
///
/// Converts an ASN.1 time value extracted from an X.509 certificate
/// into a standardized **RFC3339 / ISO-8601 timestamp string**.
///
/// If the timestamp cannot be converted, the function safely falls
/// back to the Unix epoch (`1970-01-01T00:00:00Z`).
///
/// # Arguments
///
/// * `t` – ASN.1 timestamp from an X.509 certificate.
///
/// # Returns
///
/// A UTC timestamp formatted as an RFC3339 string.
///
/// # Notes
///
/// This helper is used when extracting certificate validity
/// periods (`not_before`, `not_after`) from attestation
/// root certificates.
fn format_x509_time(t: x509_parser::time::ASN1Time) -> String {
    use chrono::{LocalResult, TimeZone, Utc};

    // timestamp_opt returns LocalResult<DateTime<Utc>>
    let dt = match Utc.timestamp_opt(t.timestamp(), 0) {
        LocalResult::Single(datetime) => datetime,
        // Fallback to Unix Epoch if the timestamp is invalid or ambiguous
        _ => match Utc.timestamp_opt(0, 0) {
            LocalResult::Single(epoch) => epoch,
            LocalResult::Ambiguous(epoch, _) => epoch,
            LocalResult::None => return "1970-01-01T00:00:00Z".to_string(),
        },
    };

    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Helper for JWT parts (URL Safe, No Padding)
///
/// Decodes a **JWT component** using URL-safe Base64 without padding,
/// which is the encoding format used by standard JWT tokens.
///
/// # Arguments
///
/// * `input` – Encoded JWT component.
/// # Errors
///
/// This function may return the errors:
///
/// # Returns
///
/// * `Ok(Vec<u8>)` – Decoded bytes.
/// * `Err(base64::DecodeError)` – If decoding fails.
///
/// # Notes
///
/// JWT payloads typically omit Base64 padding characters (`=`),
/// therefore the `URL_SAFE_NO_PAD` engine is used.
pub fn base64_decode_jwt_part(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(input.trim())
}

/// Helper for Certificates (Standard Base64, may have Padding)
///
/// Decodes Base64 encoded certificate data.
///
/// FIDO metadata providers may encode certificates using either
/// **standard Base64** or **URL-safe Base64**, so this helper attempts
/// both decoding strategies.
///
/// # Arguments
///
/// * `input` – Base64 encoded certificate string.
/// # Errors
///
/// This function may return the errors:
///
/// # Returns
///
/// * `Ok(Vec<u8>)` – Decoded DER certificate bytes.
/// * `Err(base64::DecodeError)` – If both decoding attempts fail.
pub fn base64_decode_standard(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    // Some MDS providers use standard, some use URL safe. We try both.
    STANDARD.decode(input.trim()).or_else(|_| {
        use base64::engine::general_purpose::URL_SAFE;
        URL_SAFE.decode(input.trim())
    })
}

/// Compute SHA-256 fingerprint of certificate data.
///
/// Generates a hexadecimal SHA-256 fingerprint for the provided
/// certificate bytes.
///
/// Fingerprints are commonly used to uniquely identify
/// X.509 certificates in logs, databases, and security audits.
///
/// # Arguments
///
/// * `data` – DER-encoded certificate bytes.
///
/// # Returns
///
/// A lowercase hexadecimal SHA-256 hash string.
pub fn sha256_fingerprint(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Convert DER certificate to PEM format.
///
/// Encodes a DER-encoded X.509 certificate into **PEM format**,
/// which is widely used by TLS libraries and certificate stores.
///
/// # Arguments
///
/// * `der` – DER-encoded certificate bytes.
///
/// # Returns
///
/// A PEM formatted certificate string containing:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// base64 data
/// -----END CERTIFICATE-----
/// ```
///
/// # Notes
///
/// The PEM format is required by many cryptographic libraries
/// and is commonly used when constructing attestation trust anchors.
pub fn pem_encode(der: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----")
}
