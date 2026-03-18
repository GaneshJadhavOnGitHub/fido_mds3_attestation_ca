//! Runtime loading of CA list from file or embedded fallback
//!
//! This module is responsible for loading the FIDO Metadata Service (MDS3)
//! Certificate Authority (CA) list at runtime. It follows a resilient
//! multi-stage loading strategy:
//!
//! 1. Attempt to load and parse a **cached metadata blob** from the user's
//!    filesystem.
//! 2. If the cached blob is missing or corrupted, attempt to **download the
//!    latest blob** from the FIDO Metadata Service.
//! 3. If the download fails or the downloaded blob cannot be parsed,
//!    fall back to the **embedded CA list** bundled with the crate.
//!
//! This ensures that applications using the crate always have access to
//! a usable trust anchor list even in offline environments.

use super::downloader::download_latest_blob;
use super::error::FidoMds3AttestationCaError;
use super::types::ParsedBlob;
use super::universal_user_path;
use super::{embedded_ca_list, parser};

use once_cell::sync::OnceCell;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Global cache for the user-provided parsed metadata blob.
///
/// This [`OnceCell`] stores the parsed [`ParsedBlob`] loaded from a
/// user-specified FIDO Metadata Service (MDS3) JWT file.
///
/// The blob is initialized **lazily on first access** through
/// [`get_or_init_blob_cache`]. Once initialized, the parsed metadata
/// is reused for the lifetime of the process, avoiding repeated disk
/// reads and parsing.
///
/// Internally the blob is wrapped in [`Arc`] so it can be shared safely
/// across threads without copying the underlying data.
static USER_PARSED: OnceCell<Arc<ParsedBlob>> = OnceCell::new();

/// Reads a FIDO Metadata Service (MDS3) JWT blob from disk and parses it.
///
/// This helper function:
///
/// 1. Reads the JWT file from the provided filesystem path.
/// 2. Passes the JWT string to the crate's metadata parser.
/// 3. Returns the resulting [`ParsedBlob`] structure.
///
/// This function **does not cache results**. It is intended to be used
/// internally by [`get_or_init_blob_cache`] during the initial cache
/// initialization.
///
/// # Parameters
///
/// * `jwt_path` — Filesystem path to the MDS3 JWT metadata blob.
///
/// # Returns
///
/// * `Ok(ParsedBlob)` – Successfully parsed metadata blob.
/// * `Err(FidoMds3AttestationCaError)` – If the file cannot be read
///   or if parsing the metadata blob fails.
///
/// # Errors
///
/// * [`FidoMds3AttestationCaError::IoError`] – If the JWT file cannot be read.
/// * Any parsing error returned by the crate's metadata parser.
///
/// # Logging
///
/// * Emits a `debug` log when reading the JWT file.
/// * Emits an `error` log if parsing fails.
pub fn load_blob_and_call_parser<P: AsRef<Path>>(
    jwt_path: P,
) -> Result<ParsedBlob, FidoMds3AttestationCaError> {
    log::debug!("Reading JWT from: {}", jwt_path.as_ref().display());

    let jwt_data =
        fs::read_to_string(&jwt_path).map_err(|e| FidoMds3AttestationCaError::IoError {
            path: jwt_path.as_ref().display().to_string(),
            reason: e.to_string(),
        })?;

    parser::parse_blob(&jwt_data).map_err(|e| {
        log::error!("Failed to parse user CA list: {e}");
        e
    })
}

#[allow(rustdoc::private_intra_doc_links)]
/// Lazily loads and caches a user-provided FIDO Metadata Service (MDS3) blob.
///
/// This function initializes the global [`USER_PARSED`] cache on first access
/// by reading and parsing the JWT metadata file from the provided path.
/// Subsequent calls return the **cached parsed blob** without re-reading
/// the file or re-parsing the metadata.
///
/// The parsed blob is wrapped in [`Arc`] to allow efficient shared access
/// across threads.
///
/// # Parameters
///
/// * `jwt_path` — Filesystem path to the MDS3 JWT metadata blob.
///
/// # Errors
///
/// This function may return the errors:
///
/// # Returns
///
/// * `Ok(Arc<ParsedBlob>)` – A shared reference to the parsed metadata blob.
/// * `Err(FidoMds3AttestationCaError)` – If reading or parsing the blob fails.
///
/// # Behavior
///
/// * On the **first call**, the JWT file is read from disk and parsed.
/// * On **subsequent calls**, the cached blob is returned immediately,
///   avoiding disk I/O and parsing overhead.
///
/// # Logging
///
/// * Logs successful initialization of the cache at `info` level.
///
/// # Example
///
/// ```ignore
/// let blob = get_or_init_blob_cache("/home/user/.local/share/fido_mds3_attestation_ca/ca_list.jwt")?;
/// println!("Loaded {} metadata entries", blob.cas.len());
/// ```
pub fn get_or_init_blob_cache<P: AsRef<Path>>(
    jwt_path: P,
) -> Result<Arc<ParsedBlob>, FidoMds3AttestationCaError> {
    USER_PARSED
        .get_or_try_init(|| {
            let parsed = load_blob_and_call_parser(jwt_path)?;
            log::info!("User CA list parsed and cached successfully.");
            Ok(Arc::new(parsed))
        })
        .cloned()
}

/// Loads the FIDO MDS3 metadata blob using a resilient fallback strategy.
///
/// This function ensures that a valid [`ParsedBlob`] is returned even if
/// the local cache is missing or the network is unavailable.
///
/// The loading order is:
///
/// 1. **Cached Blob**  
///    Attempts to parse the metadata blob stored in the user cache
///    directory.
///
/// 2. **Download Latest Blob**  
///    If the cached blob is missing or corrupted, the latest blob
///    is downloaded and parsed.
///
/// 3. **Embedded Fallback**  
///    If downloading fails or the downloaded file is invalid, the
///    embedded CA list compiled into the crate is used.
///
/// # Feature Gating
///
/// **Note:** The **Embedded Fallback** returns an **empty list** by default to minimize binary size.
/// To include the actual FIDO metadata snapshot as a recovery mechanism, enable the `embedded`
/// feature in Cargo.toml.
///
/// # Errors
///
/// This function may return the errors:
///
/// # Returns
///
/// * `Ok(Arc<ParsedBlob>)` containing the parsed metadata blob.
/// * `Err(FidoMds3AttestationCaError)` if the cache path cannot be
///   resolved.
///
/// # Logging
///
/// The function emits debug and error logs describing the loading
/// process, including cache hits, parsing failures, download attempts,
/// and fallback usage.
///
/// # Thread Safety
///
/// The returned [`ParsedBlob`] is wrapped in [`Arc`] to allow
/// safe shared access across threads without additional copying.
pub fn load_jwt() -> Result<Arc<ParsedBlob>, FidoMds3AttestationCaError> {
    let jwt_path = universal_user_path()?;
    log::debug!("Universal path resolved to {jwt_path:?}");

    // 1️⃣ Try blob at universal use path.
    if jwt_path.exists() {
        log::debug!("Cached blob found. Attempting parse...");

        match get_or_init_blob_cache(&jwt_path) {
            Ok(parsed) => {
                log::debug!("Cached blob parsed successfully.");
                return Ok(parsed);
            }

            Err(e) => {
                log::error!("Cached blob appears corrupted ({e:?}). Removing and retrying...");
                let _ = fs::remove_file(&jwt_path);
            }
        }
    } else {
        log::error!("No cached blob found.");
    }

    // 2️⃣ Download fresh blob
    log::debug!("Attempting to download latest FIDO MDS3 blob...");

    match download_latest_blob() {
        Ok(downloaded_path) => {
            log::debug!("Download successful. File saved to {downloaded_path:?}",);

            match get_or_init_blob_cache(&downloaded_path) {
                Ok(parsed) => {
                    log::debug!("Downloaded blob parsed successfully.");
                    return Ok(parsed);
                }

                Err(e) => {
                    log::error!("Downloaded blob invalid ({e:?}). Removing corrupted file...",);
                    let _ = fs::remove_file(&downloaded_path);
                }
            }
        }

        Err(e) => {
            log::error!("Download failed with error: {e:?}. Falling back to embedded list.",);
        }
    }

    // 3️⃣ Final fallback
    log::debug!("Using embedded CA list as final fallback.");
    Ok(embedded_ca_list())
}
