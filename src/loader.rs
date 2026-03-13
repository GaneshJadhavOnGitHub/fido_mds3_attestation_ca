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

use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Parses a metadata blob file and converts it into a [`ParsedBlob`].
///
/// This function reads the file contents from the provided path and
/// invokes the crate parser to convert the raw metadata blob into
/// structured data.
///
/// # Parameters
///
/// * `path` - Path to the metadata blob file.
///
/// # Returns
///
/// * `Ok(Arc<ParsedBlob>)` if parsing succeeds.
/// * `Err(FidoMds3AttestationCaError)` if the file cannot be read
///   or if parsing fails.
///
/// # Errors
///
/// Returns [`FidoMds3AttestationCaError::FileNotFoundError`] if the
/// file cannot be read from disk.
fn call_parser(path: &Path) -> Result<Arc<ParsedBlob>, FidoMds3AttestationCaError> {
    log::debug!("Attempting to parse blob from {path:?}");

    let content = std::fs::read_to_string(path)
        .inspect_err(|e| log::error!("File not found error : {e}"))
        .map_err(|_| FidoMds3AttestationCaError::FileNotFoundError(path.to_path_buf()))?;

    let parsed = parser::parse_blob(&content)?;
    Ok(Arc::new(parsed))
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

    // 1️⃣ Try cached blob
    if jwt_path.exists() {
        log::debug!("Cached blob found. Attempting parse...");

        match call_parser(&jwt_path) {
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

            match call_parser(&downloaded_path) {
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
