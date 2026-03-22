//! Downloader for the FIDO MDS3 CA list blob.
//!
//! This module provides functionality for retrieving the latest
//! **FIDO Metadata Service (MDS3) blob** from the official FIDO server
//! and storing it locally.
//!
//! This module is library-safe and can be used from:
//! - loader.rs
//!
//! It performs no logging or CLI output and returns errors instead.
//!
//! The download process is designed to be robust and safe:
//!
//! - Uses a **network timeout** to avoid hanging requests.
//! - Handles **HTTP rate limiting (Error 429)** explicitly.
//! - Writes the file using a **temporary file and atomic rename**
//!   to prevent partially written files.
//! - Uses a **lock file** to prevent multiple processes from
//!   downloading the blob simultaneously.
//! - Automatically **cleans stale lock files** older than 5 minutes.

use super::universal_user_path;
use crate::constants::BLOB_URL;
use crate::error::FidoMds3AttestationCaError;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Download the latest FIDO MDS3 blob to the default user data location.
///
/// The destination path is determined using the platform-specific
/// [`universal_user_path()`] helper, which resolves the correct user
/// data directory depending on the operating system.
///
/// # Behavior
///
/// - Resolves the local cache path for the metadata blob.
/// - Downloads the blob from the FIDO Metadata Service.
/// - Saves the blob to the resolved location using [`download_to`].
///
/// # Returns
///
/// * `Ok(PathBuf)` – The final filesystem path where the blob was stored.
/// * `Err(FidoMds3AttestationCaError)` – If the path cannot be resolved
///   or the download fails.
///
/// # Errors
///
/// This function may return errors in the following situations:
///
/// - Failure to resolve the platform-specific cache directory
/// - Network or HTTP errors while downloading the blob
/// - Filesystem errors while saving the file
pub fn download_latest_blob() -> Result<PathBuf, FidoMds3AttestationCaError> {
    let path = universal_user_path().map_err(|e| {
        log::error!("Failed to resolve cache path: {e}");
        FidoMds3AttestationCaError::DownloadError(e.to_string())
    })?;

    download_to(&path).map_err(|e| {
        log::error!("Failed to download metadata blob: {e}");
        FidoMds3AttestationCaError::DownloadError(e.to_string())
    })?;

    log::debug!("Metadata blob downloaded successfully to {path:?}");

    Ok(path)
}

/// Download the FIDO MDS3 blob to a custom filesystem path.
///
/// This function performs the actual network download and writes the
/// metadata blob to the specified path.
///
/// # Behavior
///
/// - Creates an HTTP client with a **30-second timeout**.
/// - Downloads the metadata blob from [`BLOB_URL`].
/// - Handles **rate limiting (HTTP 429)** explicitly.
/// - Uses a **temporary file (`.tmp`)** to ensure atomic writes.
/// - Uses a **lock file (`.lock`)** to prevent concurrent downloads.
/// - Ensures the parent directory exists before writing the file.
/// - Replaces the existing cache atomically once the download completes.
///
/// # Arguments
///
/// * `path` – The destination path where the downloaded blob should be stored.
///
/// # Errors
///
/// Returns [`FidoMds3AttestationCaError`] if:
///
/// - The HTTP request fails
/// - The server returns an unexpected status code
/// - The system is rate-limited by the FIDO server (HTTP 429)
/// - Filesystem operations fail (directory creation, writing, renaming)
///
/// # Concurrency Safety
///
/// To avoid multiple processes downloading the metadata blob simultaneously,
/// this function creates a **lock file** next to the destination path.
///
/// If a lock file already exists:
///
/// - If it is older than **5 minutes**, it is considered stale and removed.
/// - Otherwise, the function returns an error indicating another process
///   is currently performing the download.
pub fn download_to(path: &Path) -> Result<(), FidoMds3AttestationCaError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();

    // Handle HTTP rate limiting and network errors explicitly
    let response = match agent.get(BLOB_URL).call() {
        Ok(resp) => resp,

        // FIDO Metadata Service rate limiting (HTTP 429)
        Err(ureq::Error::Status(429, _)) => {
            log::error!("❌ Error 429: Rate-limited by FIDO. Please wait for few minutes.");
            return Err(FidoMds3AttestationCaError::RateLimitedError);
        }

        // Other HTTP errors
        Err(ureq::Error::Status(code, _)) => {
            log::error!("❌ Server returned HTTP error {code}. Download failed.");
            return Err(FidoMds3AttestationCaError::DownloadError(format!(
                "HTTP request failed with status code {code}"
            )));
        }

        // Network unavailable / DNS / connection failures
        Err(ureq::Error::Transport(e)) => {
            log::error!("❌ Network error while contacting FIDO server: {e}");
            return Err(FidoMds3AttestationCaError::DownloadError(format!(
                "Network error while downloading FIDO MDS blob: {e}",
            )));
        }
    };

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::error!("❌ Failed to create directory {}: {e}", parent.display());
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }
        }
    }

    // Lock file to prevent multiple processes downloading simultaneously
    let lock_path = path.with_extension("lock");

    // Clean stale lock file (older than 5 minutes)
    if let Ok(meta) = std::fs::metadata(&lock_path) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap_or_default().as_secs() > 300 {
                let _ = std::fs::remove_file(&lock_path);
            }
        }
    }

    let _lock = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(_) => {
            log::error!("❌ Another download is already running.");
            return Err(FidoMds3AttestationCaError::DownloadError(
                "Another process is downloading the blob".into(),
            ));
        }
    };

    // Temporary file for atomic download
    let tmp_path = path.with_extension("tmp");

    let mut reader = response.into_reader();

    let mut file = match File::create(&tmp_path) {
        Ok(file) => file,
        Err(e) => {
            log::error!("Error creating file {}: {e}", tmp_path.display());
            return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
        }
    };

    let mut buffer = [0u8; 8192];

    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => {
                log::debug!("Reached end of stream (0 bytes read).");
                0
            }
            Ok(n) => n,
            Err(e) => {
                log::error!("Failed to read from FIDO MDS3 stream: {e}");
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }
        };

        if n == 0 {
            break;
        }

        match file.write_all(&buffer[..n]) {
            Ok(_) => {
                log::trace!("Successfully wrote {n} bytes to the cache file.");
            }
            Err(e) => {
                log::error!("Failed to write FIDO MDS3 blob to disk: {e}");
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }
        };
    }

    match file.sync_all() {
        Ok(_) => log::debug!("FIDO MDS3 file buffers successfully flushed to disk."),
        Err(e) => {
            log::error!("Failed to sync FIDO MDS3 cache to hardware: {e}");
            return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
        }
    };

    // Atomic replace
    match std::fs::rename(&tmp_path, path) {
        Ok(_) => log::debug!(
            "Successfully updated FIDO MDS3 cache at: {}",
            path.display()
        ),
        Err(e) => {
            log::error!(
                "Failed to move temporary file {} to final path {}: {e}",
                tmp_path.display(),
                path.display(),
            );
            return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
        }
    };

    // Remove lock file
    let _ = std::fs::remove_file(lock_path);

    Ok(())
}
