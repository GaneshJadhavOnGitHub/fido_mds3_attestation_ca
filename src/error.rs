//! Custom error handler for crate.
//!
//! This module defines the unified error type used across the
//! `fido-mds3-attestation-ca` crate. All operations in the crate
//! return this error type to provide consistent error handling
//! and meaningful diagnostics.
//!
//! The errors cover common failure scenarios encountered when
//! working with the FIDO Metadata Service (MDS3) blob, including:
//!
//! - JWT parsing failures
//! - Base64 decoding errors
//! - JSON serialization or deserialization failures
//! - Missing fields in the metadata blob
//! - File and I/O related errors
//! - Metadata extraction failures
//! - Network download failures
//!
//! The error type uses the `thiserror` derive macro to automatically
//! implement `std::error::Error` and provide human-readable error
//! messages.

use std::path::PathBuf;
use thiserror::Error;

/// The primary error type for the `fido-mds3-attestation-ca` crate.
///
/// This enum represents all recoverable and unrecoverable errors
/// that can occur while downloading, parsing, and processing the
/// FIDO Metadata Service (MDS3) blob.
///
/// Each variant represents a specific failure scenario and carries
/// additional context where appropriate.
///
/// The implementation uses the `thiserror` derive macro to provide
/// automatic implementations for:
///
/// - `std::error::Error`
/// - `Display` formatting
/// - `From` conversions for supported error types
///
/// This makes error propagation ergonomic when using the `?` operator.
#[derive(Debug, Error)]
pub enum FidoMds3AttestationCaError {
    /// Returned when the JWT blob does not conform to the expected
    /// structure (for example, missing header, payload, or signature).
    #[error("Invalid JWT structure: {0}")]
    InvalidJwtError(String),

    /// Returned when Base64 decoding fails while processing
    /// certificates or JWT payload segments.
    #[error("Base64 decode failed: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Returned when JSON parsing or serialization fails while
    /// processing the metadata blob.
    #[error("JSON serialization/deserialization failed: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Returned when an expected field is missing from the
    /// metadata statement or metadata blob.
    #[error("Missing expected field in MDS blob: {0}")]
    MissingFieldError(String),

    /// Returned when UTF-8 decoding fails while converting
    /// byte data into a string.
    #[error("Invalid UTF-8 sequence in payload")]
    InvalidUtf8Error,

    /// Represents generic input/output errors occurring during
    /// filesystem operations such as reading or writing files.
    #[error("IO error at {path}: {reason}")]
    IoError {
        ///Filesystem path where the I/O operation failed.
        path: String,
        ///Underlying error message describing the failure.
        reason: String,
    },

    /// Returned when the expected metadata blob file cannot
    /// be found at the specified filesystem path.
    #[error("File not found at path: {0}")]
    FileNotFoundError(PathBuf),

    /// Returned when a file extension does not match any
    /// supported CA list formats.
    #[error("Unknown file extension for CA list: {0}")]
    UnknownExtensionError(String),

    /// Returned when the FIDO server rate-limits a metadata
    /// download request (HTTP 429).
    #[error("FIDO server rate-limited the request (429). Please wait before retrying.")]
    RateLimitedError,

    /// Returned when no CA list is available and the embedded
    /// fallback has been disabled.
    #[error("No CA list found and embedded fallback is disabled")]
    NoFallbackError,

    /// Returned when converting metadata entries into
    /// `WebAuthn` compatible structures fails.
    #[error("WebAuthn-rs conversion error: {0}")]
    WebauthnConversionError(String),

    /// Represents generic parsing errors encountered while
    /// interpreting metadata structures.
    #[error("Parsing error: {0}")]
    ParsingError(String),

    /// Returned when extracting trust anchors or metadata
    /// information from the parsed blob fails.
    #[error("Extraction error: {0}")]
    ExtractionError(String),

    /// Returned when Base64 decoding fails for a specific
    /// device certificate during metadata processing.
    #[error("Base64 decode failed for device {device_name}: {reason}")]
    Base64DecodeError {
        ///Human-readable name of the device whose certificate failed to decode.    
        device_name: String,
        ///Underlying error message describing the decoding failure.
        reason: String,
    },

    /// Returned when downloading the metadata blob from the
    /// FIDO Metadata Service fails.
    #[error("Blob download failed: {0}")]
    DownloadError(String),

    /// Returned when resolving the universal user path used
    /// for storing cached metadata fails.
    #[error("Universal Path Error: {0}")]
    UniversalPathError(String),
}

/// A convenient type alias for `Result` values returned within this crate.
///
/// This alias simplifies function signatures across the crate by replacing
/// verbose `Result<T, FidoMds3AttestationCaError>` declarations with
/// `FidoMds3AttestationCaResult<T>`.
///
/// # Example
///
/// ```rust
/// use fido_mds3_attestation_ca::error::FidoMds3AttestationCaResult;
///
/// fn example() -> FidoMds3AttestationCaResult<()> {
///     Ok(())
/// }
/// ```
pub type FidoMds3AttestationCaResult<T> = Result<T, FidoMds3AttestationCaError>;
