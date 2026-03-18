//! # `fido_mds3_attestation_ca`
//!
//! A Rust library for parsing the **FIDO Metadata Service (MDS) v3 blob**
//! and producing an [`AttestationCaList`] compatible with
//! [`webauthn_rs::Webauthn::start_attested_passkey_registration`].
//!
//! ## Compatibility
//!
//! This crate is designed to work with
//! [`webauthn-rs`](https://crates.io/crates/webauthn-rs) **v0.5.4**.
//!
//!
//! ## Typical Flow
//!
//! 1. Download or load the FIDO MDS3 blob
//! 2. Parse the metadata entries
//! 3. Convert them into an `AttestationCaList` which
//!    can be passed to `start_attested_passkey_registration` function.

#![warn(unused_extern_crates)]

use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use uuid::Uuid;
use webauthn_rs::prelude::{AttestationCaList, AttestationCaListBuilder};

use error::FidoMds3AttestationCaError;
use types::{AttestationFilter, ParsedBlob};

use constants::BLOB_FILE_NAME;
use constants::EMBEDDED_JWT;

pub mod constants;
pub mod downloader;
pub mod error;
pub mod loader;
pub mod logging;
pub mod parser;
pub mod types;

/// In-memory cache for the generated **attestation trust anchor list**.
///
/// This [`OnceLock`] stores the [`AttestationCaList`] produced when
/// [`AttestationFilter::TrustAnchors`] is requested via [`build_ca_list`].
///
/// The list is computed **only once during the lifetime of the process**.
/// On the first request, the crate loads the FIDO Metadata Service (MDS3)
/// blob, extracts all valid attestation trust anchors, and stores the
/// resulting list here.
///
/// Subsequent calls return the cached list immediately, avoiding:
///
/// - Re-loading the metadata blob
/// - Re-parsing the metadata
/// - Re-building the trust anchor list
///
/// This significantly improves performance since the MDS3 blob can be
/// several megabytes in size.
///
/// [`OnceLock`] guarantees thread-safe one-time initialization.
static TRUST_ANCHORS_CACHE: OnceLock<AttestationCaList> = OnceLock::new();

/// In-memory cache for the generated **FIDO-certified attestation trust anchors**.
///
/// This [`OnceLock`] stores the [`AttestationCaList`] produced when
/// [`AttestationFilter::FidoCertifiedTrustAnchorsOnly`] is requested via
/// [`build_ca_list`].
///
/// The list is initialized **only once** by extracting trust anchors from
/// authenticators whose status indicates **FIDO certification** according
/// to the FIDO Metadata Service (MDS3).
///
/// After the first initialization, all subsequent requests reuse the cached
/// list, eliminating repeated metadata processing and improving runtime
/// performance.
///
/// [`OnceLock`] ensures thread-safe lazy initialization.
static FIDO_CERTIFIED_CACHE: OnceLock<AttestationCaList> = OnceLock::new();

/// Universal user data path for downloading/storing CA list
///
/// Platform-specific:
/// - Linux: ~/.`local/share/fido_mds3_attestation_ca/ca_list.jwt`
/// - macOS: ~/`Library/Application Support/fido_mds3_attestation_ca/ca_list.jwt`
/// - Windows: %`LOCALAPPDATA%\fido_mds3_attestation_ca\ca_list.jwt`
///
/// This function resolves a platform-appropriate user data directory
/// using the [`dirs`](https://docs.rs/dirs/latest/dirs/) crate and
/// constructs the full path where the FIDO MDS3 metadata blob
/// (`ca_list.jwt`) should be stored.
///
/// If the application directory does not exist, the function
/// automatically creates it to ensure the path is ready for use.
///
/// # Returns
///
/// * `Ok(PathBuf)` – Absolute path where the metadata blob should be stored.
/// * `Err(FidoMds3AttestationCaError)` – If the OS user data directory
///   cannot be determined or the directory cannot be created.
///
/// # Errors
///
/// This function returns [`FidoMds3AttestationCaError::UniversalPathError`] when:
///
/// - The operating system does not provide a usable local data directory.
/// - The crate fails to create the application-specific directory.
///
/// # Example
///
/// ```rust
/// use fido_mds3_attestation_ca::universal_user_path;
///
/// let path = universal_user_path().expect("Failed to resolve path");
/// println!("Metadata blob path: {:?}", path);
/// ```
///
/// # References
///
/// - `dirs` crate documentation: <https://docs.rs/dirs/latest/dirs/>
/// - Rust filesystem APIs: <https://doc.rust-lang.org/std/fs/>
pub fn universal_user_path() -> Result<PathBuf, FidoMds3AttestationCaError> {
    // 1. Determine the base directory
    let base_dir = match dirs::data_local_dir().or_else(dirs::data_dir) {
        Some(dir) => dir,
        None => {
            let err_msg =
                "Could not determine local data directory from OS environment".to_string();
            log::error!("Critical Error: {err_msg}");
            return Err(FidoMds3AttestationCaError::UniversalPathError(err_msg));
        }
    };

    let crate_name = env!("CARGO_PKG_NAME");
    let app_dir = base_dir.join(crate_name);
    let full_path = app_dir.join(BLOB_FILE_NAME);

    // 2. Self-Healing: Ensure the directory exists
    if !app_dir.exists() {
        match std::fs::create_dir_all(&app_dir) {
            Ok(_) => log::debug!("Created application data directory at: {app_dir:?}"),
            Err(e) => {
                log::error!("Failed to create application directory {app_dir:?}: {e}");
                return Err(FidoMds3AttestationCaError::UniversalPathError(format!(
                    "FileSystem Error: {e}"
                )));
            }
        }
    }

    // This is useful for debugging but should be 'debug' level to avoid terminal noise
    log::debug!("LIB : Universal path resolved to: {full_path:?}");

    Ok(full_path)
}

/// Lazily initialized embedded CA list parsed from the bundled JWT.
///
/// This static value ensures that the embedded FIDO MDS3 metadata blob
/// is parsed **only once** during the lifetime of the program. The parsed
/// result is stored in an [`Arc`] so it can be cheaply cloned and shared
/// across the crate without repeated parsing.
///
/// The initialization occurs on **first access** using [`once_cell::sync::Lazy`].
///
/// # Behavior
///
/// * On the first access, the embedded JWT (`EMBEDDED_JWT`) is parsed using
///   [`parser::parse_blob`].
/// * If parsing succeeds, the parsed metadata blob is cached and reused.
/// * If parsing fails, a **critical error is logged**, and an empty
///   [`ParsedBlob`] is returned to avoid crashing the application.
///
/// This mechanism provides a **safe fallback** when:
///
/// - The downloaded metadata blob is unavailable
/// - The local cache is corrupted
/// - Network access to the FIDO Metadata Service fails
///
/// # Logging
///
/// * `debug` – Initialization and cache usage
/// * `info` – Successful embedded parsing
/// * `error` – Critical failure when parsing embedded metadata
///
/// # Thread Safety
///
/// The value is wrapped in [`Arc`] so it can be safely shared across
/// multiple threads without copying the parsed structure.
///
/// # References
///
/// - `once_cell::Lazy`: <https://docs.rs/once_cell/latest/once_cell/>
/// - `Arc` shared ownership: <https://doc.rust-lang.org/std/sync/struct.Arc.html>
static EMBEDDED_PARSED: Lazy<Arc<ParsedBlob>> = Lazy::new(|| {
    log::debug!("Embedded: Initializing embedded CA list (first access)");

    match parser::parse_blob(EMBEDDED_JWT) {
        Ok(parsed) => {
            log::info!("Embedded CA list parsed successfully.");
            Arc::new(parsed)
        }
        Err(e) => {
            // CRITICAL: The embedded JWT is invalid.
            // We log this as an error so the dev sees it in production.
            log::error!(
                "CRITICAL: Failed to parse embedded CA list: {e}. Crate will operate with empty CA list.",
            );

            // Return an empty/default ParsedBlob instead of crashing.
            // This assumes ParsedBlob implements Default or has a 'new_empty' method.
            Arc::new(ParsedBlob::default())
        }
    }
});

/// Returns the parsed embedded CA list.
///
/// This function provides access to the **cached embedded metadata blob**
/// used as a fallback when downloading or loading the FIDO MDS3 metadata
/// fails.
///
/// The returned value is an [`Arc<ParsedBlob>`], allowing inexpensive
/// cloning and thread-safe sharing across different parts of the crate.
///
/// # Returns
///
/// * `Arc<ParsedBlob>` – Shared reference to the parsed embedded metadata.
///
/// # Behavior
///
/// * The embedded blob is parsed **only once** during program execution.
/// * Subsequent calls return a cloned [`Arc`] pointing to the same
///   cached structure.
///
/// # Example
///
/// ```rust
/// use fido_mds3_attestation_ca::embedded_ca_list;
///
/// let ca_list = embedded_ca_list();
/// println!("Loaded embedded CA entries: {:?}", ca_list);
/// ```
///
/// # References
///
/// - `Arc` documentation: <https://doc.rust-lang.org/std/sync/struct.Arc.html>
/// - FIDO Metadata Service: <https://fidoalliance.org/metadata/>
pub fn embedded_ca_list() -> Arc<ParsedBlob> {
    log::debug!("Returning cached embedded CA list");
    EMBEDDED_PARSED.clone()
}

impl ParsedBlob {
    /// Extract all attestation trust anchors (attestation root certificates authority) with valid certificates.
    /// Returns deduplicated Trust Anchors (attestation root certificates)
    /// used to verify authenticator attestation statements.
    /// supporting both AAGUIDs and AAIDs.
    ///
    /// This function scans all parsed FIDO Metadata Service (MDS3) entries
    /// and extracts **attestation root certificates** from each authenticator's
    /// metadata statement.
    ///
    /// These root certificates are used during **`WebAuthn` attestation verification**
    /// to validate the authenticity of hardware authenticators.
    ///
    /// # Extraction Process
    ///
    /// For each metadata entry:
    ///
    /// 1. **Resolve device identifier**
    ///    - The device UUID is obtained using \[`extract_uuid_strict`\].
    ///    - This supports both:
    ///      - **AAGUID** (FIDO2 authenticators)
    ///      - **AAID** (legacy U2F authenticators)
    ///
    /// 2. **Locate attestation root certificates**
    ///    - Certificates are read from:
    ///      `metadataStatement.attestationRootCertificates`
    ///
    /// 3. **Decode certificates**
    ///    - Each certificate is Base64 decoded into DER format.
    ///
    /// 4. **Insert into CA list**
    ///    - Certificates are added to [`AttestationCaListBuilder`].
    ///    - Duplicate certificates are automatically deduplicated.
    ///
    /// 5. **Skip invalid entries**
    ///    - Entries missing metadata or certificates are skipped.
    ///    - Skipped entries are counted internally.
    ///
    /// # Errors
    ///
    /// This function may return the following errors:
    ///
    /// * Base64 decoding errors return
    ///   [`FidoMds3AttestationCaError::Base64DecodeError`].
    ///
    /// * Certificate insertion failures are logged as warnings
    ///   but do **not** stop processing.
    ///
    /// This ensures that valid certificates from other authenticators
    /// are still collected.
    ///
    /// # Returns
    ///
    /// * `Ok(AttestationCaList)` — A deduplicated list of attestation
    ///   trust anchors extracted from the metadata.
    /// * `Err(FidoMds3AttestationCaError)` — If certificate decoding fails.
    ///
    /// # Logging
    ///
    /// * `warn` — Certificate insertion failures
    /// * `info` — Successful generation of the trust anchor list
    ///
    /// # References
    ///
    /// - FIDO Metadata Service specification: <https://fidoalliance.org/metadata/>
    /// - `WebAuthn` attestation model: <https://www.w3.org/TR/webauthn/>
    pub fn build_attestation_trust_anchors(
        &self,
    ) -> Result<AttestationCaList, FidoMds3AttestationCaError> {
        let mut builder = AttestationCaListBuilder::new();
        let mut _skipped_count = 0;

        for entry in &self.cas {
            let device_uuid = self.extract_uuid_strict(entry);

            let metadata = entry
                .raw_data
                .as_ref()
                .and_then(|r| r.get("metadataStatement"));

            // If metadata or certs are missing, we log a warning and skip
            let certs = metadata
                .and_then(|m| m.get("attestationRootCertificates"))
                .and_then(|c| c.as_array());

            if let Some(certs_array) = certs {
                if certs_array.is_empty() {
                    _skipped_count += 1;
                    continue;
                }

                // Process certificates safely using the bound certs_array
                for cert_val in certs_array {
                    if let Some(cert_b64) = cert_val.as_str() {
                        let der_bytes = parser::base64_decode_standard(cert_b64).map_err(|e| {
                            FidoMds3AttestationCaError::Base64DecodeError {
                                device_name: entry.device_name.clone(),
                                reason: e.to_string(),
                            }
                        })?;

                        if let Err(e) = builder.insert_device_der(
                            &der_bytes,
                            device_uuid,
                            entry.device_name.clone(),
                            BTreeMap::new(),
                        ) {
                            log::warn!(
                                "Failed to insert attestation certificate for device '{}': {}",
                                entry.device_name,
                                e
                            );
                        }
                    }
                }
            } else {
                // This handles the None case (missing metadata or attestationRootCertificates)
                _skipped_count += 1;
                continue;
            }
        }
        log::info!("Attestation trust anchor list generated successfully!");
        Ok(builder.build())
    }

    /// Build FIDO Certified attestation trust anchors list.
    /// Strictly filters to entries with `statusReports[].status = "FIDO_CERTIFIED"`
    /// and valid `attestationRootCertificates`. These are production-ready
    /// authenticators that have passed FIDO Alliance certification testing.
    ///
    /// This function iterates through the parsed FIDO Metadata Service (MDS3)
    /// entries and extracts **attestation root certificates** only from
    /// authenticators whose latest certification status indicates
    /// **FIDO certification**.
    ///
    /// # Filtering Logic
    ///
    /// For each metadata entry:
    ///
    /// 1. **Determine the latest certification status**
    ///    - The function inspects the `statusReports` array.
    ///    - The most recent report is selected based on `effectiveDate`.
    ///
    /// 2. **Validate FIDO certification level**
    ///    - Only entries with one of the following statuses are accepted:
    ///      - `FIDO_CERTIFIED`
    ///      - `FIDO_CERTIFIED_L1`
    ///      - `FIDO_CERTIFIED_L2`
    ///      - `FIDO_CERTIFIED_L3`
    ///
    /// 3. **Extract attestation certificates**
    ///    - Certificates are taken from:
    ///      `metadataStatement.attestationRootCertificates`
    ///
    /// 4. **Decode and insert certificates**
    ///    - Certificates are Base64 decoded into DER format.
    ///    - Each certificate is inserted into an [`AttestationCaListBuilder`].
    ///
    /// 5. **Associate device identifier**
    ///    - Each certificate is mapped to a stable device identifier
    ///      obtained from \[`extract_uuid_strict`\].
    ///
    /// # Errors
    ///
    /// This function may return the following errors:
    ///
    /// * If Base64 decoding fails, a
    ///   [`FidoMds3AttestationCaError::Base64DecodeError`] is returned.
    /// * Certificate insertion errors are **logged as warnings** but do not
    ///   terminate processing. This ensures that valid certificates from other
    ///   devices can still be collected.
    ///
    /// # Returns
    ///
    /// * `Ok(AttestationCaList)` – A list containing attestation trust anchors
    ///   for FIDO-certified authenticators.
    /// * `Err(FidoMds3AttestationCaError)` – If certificate decoding fails.
    ///
    /// # Logging
    ///
    /// * `warn` – Individual certificate insertion failures
    /// * `info` – Successful generation of the CA list
    ///
    /// # References
    ///
    /// - FIDO Metadata Service specification: <https://fidoalliance.org/metadata/>
    /// - `WebAuthn` specification (Attestation): <https://www.w3.org/TR/webauthn/>
    /// - FIDO Certification Levels: <https://fidoalliance.org/certification/>
    pub fn build_fido_certified_trust_anchors(
        &self,
    ) -> Result<AttestationCaList, FidoMds3AttestationCaError> {
        let mut builder = AttestationCaListBuilder::new();

        for entry in &self.cas {
            // 1. Verify Latest Status is FIDO_CERTIFIED
            let current_status = entry
                .raw_data
                .as_ref()
                .and_then(|r| r.get("statusReports"))
                .and_then(|s| s.as_array())
                .and_then(|reports| {
                    reports.iter().max_by_key(|r| {
                        r.get("effectiveDate")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                    })
                })
                .and_then(|latest| latest.get("status"))
                .and_then(|status| status.as_str())
                .unwrap_or("");

            if !matches!(
                current_status,
                "FIDO_CERTIFIED" | "FIDO_CERTIFIED_L1" | "FIDO_CERTIFIED_L2" | "FIDO_CERTIFIED_L3"
            ) {
                continue;
            }

            let device_uuid = self.extract_uuid_strict(entry);

            if let Some(metadata) = entry
                .raw_data
                .as_ref()
                .and_then(|r| r.get("metadataStatement"))
            {
                if let Some(cert_array) = metadata
                    .get("attestationRootCertificates")
                    .and_then(|c| c.as_array())
                {
                    for cert_val in cert_array {
                        if let Some(cert_b64) = cert_val.as_str() {
                            let der_bytes =
                                parser::base64_decode_standard(cert_b64).map_err(|e| {
                                    FidoMds3AttestationCaError::Base64DecodeError {
                                        device_name: entry.device_name.clone(),
                                        reason: e.to_string(),
                                    }
                                })?;

                            if let Err(e) = builder.insert_device_der(
                                &der_bytes,
                                device_uuid,
                                entry.device_name.clone(),
                                std::collections::BTreeMap::new(),
                            ) {
                                log::warn!(
                                    "Failed to insert certificate for device '{}': {e}",
                                    entry.device_name
                                );
                            }
                        }
                    }
                }
            }
        }
        log::info!("CA list of FIDO certified trust anchors generated successfully!");
        Ok(builder.build())
    }

    /// Strictly extracts the identifier from the FIDO entry.
    /// Prioritizes AAGUID (FIDO2), falls back to AAID (U2F).
    ///
    /// This function attempts to determine a stable device identifier
    /// from a [`CaEntry`](types::CaEntry) by checking multiple sources
    /// in order of preference.
    ///
    /// # Resolution Order
    ///
    /// 1. **AAGUID (FIDO2 authenticators)**
    ///    - If the entry contains a valid `aaguid` field, it is parsed
    ///      directly into a [`Uuid`].
    ///
    /// 2. **AAID (Legacy U2F authenticators)**
    ///    - If no valid `aaguid` exists, the function attempts to extract
    ///      the `"aaid"` field from the raw JSON metadata blob.
    ///    - The AAID string is deterministically mapped to a UUID using
    ///      [`Uuid::new_v5`] with [`Uuid::NAMESPACE_DNS`].
    ///
    /// 3. **Fallback**
    ///    - If neither identifier is present, the function returns
    ///      [`Uuid::nil()`].
    ///
    /// This approach ensures that **both modern FIDO2 authenticators and
    /// legacy U2F devices receive a consistent identifier**.
    ///
    /// # Returns
    ///
    /// * `Uuid` representing the authenticator identifier.
    /// * [`Uuid::nil()`] if no identifier could be determined.
    ///
    /// # Deterministic UUID Mapping
    ///
    /// When an AAID is present but no AAGUID exists, a **version-5 UUID**
    /// is generated using a namespace-based hash. This guarantees the
    /// same AAID always maps to the same UUID.
    ///
    /// # References
    ///
    /// - FIDO Metadata Service specification: <https://fidoalliance.org/metadata/>
    /// - UUID v5 (name-based UUID): <https://datatracker.ietf.org/doc/html/rfc4122>
    /// - Rust `uuid` crate documentation: <https://docs.rs/uuid/>
    pub fn extract_uuid_strict(&self, entry: &types::CaEntry) -> Uuid {
        // 1. Check top-level AAGUID (FIDO2)
        if let Some(ref aaguid_str) = entry.aaguid {
            if let Ok(u) = Uuid::parse_str(aaguid_str) {
                return u;
            }
        }

        // 2. Fallback to raw_data for AAID (U2F)
        // This digs into the JSON blob to find the "aaid" field
        let aaid_from_blob = entry
            .raw_data
            .as_ref()
            .and_then(|json| json.get("aaid"))
            .and_then(|val| val.as_str());

        if let Some(aaid_str) = aaid_from_blob {
            // Deterministic mapping of AAID string -> UUID
            return Uuid::new_v5(&Uuid::NAMESPACE_DNS, aaid_str.as_bytes());
        }

        // 3. Last resort
        Uuid::nil()
    }
}

/// Builds an [`AttestationCaList`] based on the provided [`AttestationFilter`].
///
/// This function loads the latest available FIDO Metadata Service (MDS3)
/// metadata blob and extracts attestation certificate authorities (CAs)
/// according to the requested filter.
///
/// The metadata blob is loaded using [`loader::load_jwt`], which may:
///
/// - Use a cached local metadata file
/// - Download the latest blob from the FIDO Metadata Service
/// - Fall back to an embedded metadata list if necessary
///
/// To improve performance, the resulting CA lists are **cached in memory**.
/// Once a list is generated for a specific filter, subsequent calls will
/// return the cached result without re-parsing the metadata blob.
///
/// # Supported Filters
///
/// * [`AttestationFilter::TrustAnchors`]
///   - Extracts **all available attestation trust anchors with valid certificates** from the metadata.
///
/// * [`AttestationFilter::FidoCertifiedTrustAnchorsOnly`]
///   - Extracts **only FIDO-certified trust anchors**, filtering out
///     non-fidocertified authenticators.
///
/// # Returns
///
/// * `Ok(AttestationCaList)` – Successfully built CA list based on the filter.
/// * `Err(FidoMds3AttestationCaError)` – If loading the metadata blob fails
///   or if extraction of trust anchors fails.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * [`FidoMds3AttestationCaError::ExtractionError`] – If trust anchor extraction fails.
/// * Any error returned from [`loader::load_jwt`] when retrieving the metadata blob.
///
/// # Logging
///
/// Errors encountered during extraction are logged using the crate's logger
/// before returning a corresponding error.
///
/// # References
///
/// - FIDO Metadata Service specification: <https://fidoalliance.org/metadata/>
/// - `WebAuthn` attestation trust anchors: <https://www.w3.org/TR/webauthn/>
pub fn build_ca_list(
    attestation_filter: AttestationFilter,
) -> Result<AttestationCaList, FidoMds3AttestationCaError> {
    match attestation_filter {
        AttestationFilter::TrustAnchors => {
            // Check cache first
            if let Some(cached) = TRUST_ANCHORS_CACHE.get() {
                return Ok(cached.clone());
            }

            match loader::load_jwt() {
                Ok(ca_list) => {
                    match ca_list.build_attestation_trust_anchors() {
                        Ok(result) => {
                            // Store in cache and return
                            let _ = TRUST_ANCHORS_CACHE.set(result.clone());
                            Ok(result)
                        }
                        Err(_) => {
                            let extraction_error = "Failed to extract trust anchors.";
                            log::error!("{extraction_error}");
                            Err(FidoMds3AttestationCaError::ExtractionError(
                                extraction_error.to_string(),
                            ))
                        }
                    }
                }
                Err(e) => Err(e),
            }
        }
        AttestationFilter::FidoCertifiedTrustAnchorsOnly => {
            // Check cache first
            if let Some(cached) = FIDO_CERTIFIED_CACHE.get() {
                return Ok(cached.clone());
            }

            match loader::load_jwt() {
                Ok(ca_list) => {
                    match ca_list.build_fido_certified_trust_anchors() {
                        Ok(result) => {
                            // Store in cache and return
                            let _ = FIDO_CERTIFIED_CACHE.set(result.clone());
                            Ok(result)
                        }
                        Err(_) => {
                            let extraction_error = "Failed to extract FIDO certified trust anchors";
                            log::error!("{extraction_error}");
                            Err(FidoMds3AttestationCaError::ExtractionError(
                                extraction_error.to_string(),
                            ))
                        }
                    }
                }
                Err(e) => Err(e),
            }
        } // FidoCertifiedTrustAnchorsOnly Block Ends Here.
    } // Match Filter Ends Here
} // Function Ends Here 
