//! Core data types for FIDO MDS3 Attestation CA Lists.
//!
//! This module defines the core data structures used to represent
//! parsed information from the **FIDO Metadata Service (MDS) v3 blob**.
//!
//! The types here act as an intermediate representation between the
//! raw metadata blob and the final `AttestationCaList` structure used
//! by `WebAuthn` verification workflows.
//!
//! # Overview
//!
//! The parsing process typically follows this flow:
//!
//! 1. Download or load the **FIDO MDS3 JWT blob**.
//! 2. Decode and parse metadata entries.
//! 3. Extract attestation root certificates.
//! 4. Convert them into an `AttestationCaList`.
//!
//! The primary structures provided by this module are:
//!
//! - [`ParsedBlob`] – Container representing the parsed metadata blob.
//! - [`CaEntry`] – Individual attestation certificate authority entry.
//! - [`AttestationFilter`] – Filters used when selecting attestation CAs.
//!
//! These types are designed to be easily serializable and deserializable
//! using [`serde`], allowing them to be cached or inspected during
//! debugging and development.
//!
//! # Relationship to FIDO Metadata Service
//!
//! The **FIDO Metadata Service (MDS)** publishes metadata describing
//! certified authenticators and their attestation certificates.
//! This crate extracts relevant certificate authority information from
//! those metadata entries.
//!
//! The extracted CA information can then be used to construct an
//! attestation trust anchor list for `WebAuthn` attestation verification.
//!
//! # Serialization
//!
//! All primary structures implement [`Serialize`] and [`Deserialize`],
//! allowing them to be:
//!
//! - cached to disk
//! - inspected in logs
//! - exported for debugging or auditing purposes
//!
//! # Notes
//!
//! - Time values use [`chrono::DateTime<Utc>`] for consistency.
//! - Raw metadata fields are optionally preserved for debugging.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Main CA list structure
///
/// This structure represents the parsed contents of a FIDO MDS3 metadata
/// blob after extraction of attestation certificate authorities.
///
/// It acts as a container for all parsed [`CaEntry`] records and provides
/// metadata about the parsing process.
///
/// # Fields
///
/// * `generated_at` – Timestamp indicating when this parsed structure
///   was created.
/// * `total_entries` – Total number of CA entries extracted from the blob.
/// * `cas` – Collection of parsed attestation certificate authority entries.
///
/// # Usage
///
/// This structure is typically produced by the crate's parser and later
/// consumed when constructing an `AttestationCaList`.
///
/// # Serialization
///
/// The structure implements [`Serialize`] and [`Deserialize`] so it can
/// be cached or exported for debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBlob {
    ///Timestamp indicating when this parsed structure was created.
    pub generated_at: DateTime<Utc>,

    ///Total number of CA entries extracted from the blob.
    pub total_entries: usize,

    ///Collection of parsed attestation certificate authority entries.
    pub cas: Vec<CaEntry>,
}

impl Default for ParsedBlob {
    /// Creates an empty [`ParsedBlob`] instance.
    ///
    /// The default implementation initializes:
    ///
    /// - `generated_at` with the current UTC timestamp.
    /// - `total_entries` as `0`.
    /// - `cas` as an empty vector.
    ///
    /// This is primarily useful when initializing a placeholder structure
    /// before populating it with parsed metadata entries.
    fn default() -> Self {
        Self {
            // Use the current time as a placeholder for the "empty" state
            generated_at: Utc::now(),

            total_entries: 0,

            cas: Vec::new(),
        }
    }
}

/// Individual CA entry from a certified authenticator
///
/// Represents a single **attestation certificate authority entry**
/// extracted from a FIDO MDS3 metadata statement.
///
/// Each entry corresponds to an authenticator model and contains
/// the certificate and metadata required for attestation verification.
///
/// These entries are later transformed into trust anchors used by
/// `WebAuthn` attestation validation.
///
/// # Fields
///
/// - `aaguid` – AAGUID (Authenticator Attestation Global Unique Identifier)
///   identifying the authenticator model.
/// - `device_name` – Human-readable authenticator name.
/// - `subject` – Distinguished Name (DN) of the certificate subject.
/// - `certificate_pem` – PEM-encoded root certificate used for attestation.
/// - `fingerprint` – SHA-256 fingerprint of the certificate.
/// - `not_before` / `not_after` – Certificate validity period.
/// - `attestation_types` – Supported attestation types such as
///   `basic_full`, `basic_surrogate`, etc.
/// - `protocol_family` – Protocol family supported by the authenticator
///   (e.g., `fido2`, `u2f`).
/// - `raw_data` – Optional raw metadata entry preserved for debugging
///   or inspection.
///
/// # Notes
///
/// Not all metadata entries include an `aaguid`, particularly for
/// legacy authenticators.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaEntry {
    /// AAGUID (Authenticator Attestation Global Unique Identifier)
    pub aaguid: Option<String>,

    /// Human-readable device name
    pub device_name: String,

    /// Certificate Subject DN
    pub subject: String,

    /// PEM-encoded root certificate
    pub certificate_pem: String,

    /// SHA-256 fingerprint of certificate
    pub fingerprint: String,

    /// Validity period
    /// Certificate validity start time (Not Before).
    ///
    /// Represents the timestamp from which the attestation root certificate
    /// is considered valid. Typically derived from the X.509 certificate
    /// `notBefore` field and encoded as a string (e.g., ISO 8601 format).
    pub not_before: String,

    /// Certificate validity end time (Not After).
    ///
    /// Represents the timestamp after which the attestation root certificate
    /// is no longer valid. Typically derived from the X.509 certificate
    /// `notAfter` field and encoded as a string (e.g., ISO 8601 format).
    pub not_after: String,

    /// Supported attestation types (`basic_full`, `basic_surrogate`, etc.)
    pub attestation_types: Vec<String>,

    /// Protocol family (fido2, u2f, etc.)
    pub protocol_family: String,

    /// Raw data preserved for debugging or inspection.
    //pub raw_data: Option<serde_json::Value>,

    /// Raw data preserved for debugging or inspection.
    pub raw_data: Option<Arc<serde_json::Value>>,
}

/// Filters applied to `AttestationCaList`
///
/// This enum controls which attestation certificate authorities
/// should be included when constructing an `AttestationCaList`.
///
/// Different applications may require different levels of trust
/// depending on their security requirements.
///
/// # Variants
///
/// * `TrustAnchors`
///
///   Includes **all attestation trust anchors** with valid certificates
///   extracted from the metadata blob.
///
/// * `FidoCertifiedTrustAnchorsOnly`
///
///   Includes only attestation certificate authorities associated with
///   authenticators that have passed **FIDO Alliance certification**.
///
/// # Usage
///
/// These filters allow applications to restrict which authenticators
/// are trusted during attestation verification.
///
/// For example:
///
/// - High-security environments may allow only certified authenticators.
/// - Development environments may accept all trust anchors.
pub enum AttestationFilter {
    ///All attestation trust anchors (attestation root certificate authorities) with valid certificates.
    TrustAnchors,
    ///FIDO Certified attestation trust anchors or Attestation CA's who have passed FIDO Alliance certification testing.
    FidoCertifiedTrustAnchorsOnly,
}
