//! Build module for fido_mds3_attestation_ca

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

/// URL to download Fido Mds3 blob
const BLOB_URL: &str = "https://mds3.fidoalliance.org/";

/// Blob file name to be used.
const BLOB_FILE_NAME: &str = "ca_list.jwt";

/// Initializes logging for the build script.
///
/// This helper configures the [`env_logger`] backend so that log messages
/// emitted during the build process (e.g., `log::info!`, `log::debug!`,
/// `log::error!`) can be controlled via standard environment variables
/// such as `RUST_LOG`.
///
/// The logger initialization is attempted only once. If the logger has
/// already been initialized or initialization fails for any reason,
/// the error is printed to `stderr` and the build process continues.
///
/// This approach ensures that logging failures during the build phase
/// do not prevent the crate from compiling.
///
/// # Behavior
///
/// - Reads logging configuration from environment variables.
/// - Enables structured logging for build-time operations.
/// - Falls back to `stderr` output if initialization fails.
///
/// # Notes
///
/// Build scripts run in a separate process during compilation. Using a
/// logger helps diagnose issues such as network failures, filesystem
/// permission errors, or incorrect cache paths while preparing build
/// artifacts.
///
/// # Example
///
/// Logging can be enabled during build using:
///
/// ```bash
/// RUST_LOG=debug cargo build
/// ```
///
/// This will display debug logs emitted by the build script.
fn init_logger() {
    if let Err(e) = env_logger::Builder::from_env(env_logger::Env::default()).try_init() {
        eprintln!("Failed to initialize build logger: {e}");
    }
}

/// Entry point for the crate's build script.
///
/// This build script ensures that a cached copy of the **FIDO Metadata
/// Service (MDS) v3 blob** is available locally before compilation
/// completes. The blob is stored in a universal cache location so that
/// subsequent builds can reuse it without performing additional network
/// downloads.
///
/// The build process follows these steps:
///
/// 1. Initialize logging for build-time diagnostics.
/// 2. Register file change triggers using Cargo directives.
/// 3. Determine a universal cache path for the MDS blob.
/// 4. Create the cache directory if it does not exist.
/// 5. Check whether the blob already exists in the cache.
/// 6. If missing, attempt to download and cache the blob.
///
/// If the download fails, the build will still succeed. In that case,
/// the crate's runtime loader will attempt to retrieve the blob when
/// the library is used.
///
/// # Cargo Build Triggers
///
/// The script instructs Cargo to rerun the build script when:
///
/// - `build.rs` changes
/// - the bundled `data/ca_list.jwt` file changes
/// - the resolved cache file changes
///
/// This ensures that updates to the metadata blob or build logic
/// correctly invalidate previous build artifacts.
///
/// # Errors
///
/// This function returns an error if:
///
/// - The universal cache path cannot be determined.
/// - The cache directory cannot be created.
///
/// Network failures during blob download **do not cause the build
/// to fail**. Instead, the error is logged and runtime fallback
/// mechanisms will handle retrieval.
///
/// # Returns
///
/// * `Ok(())` if the build script completed successfully.
/// * `Err(Box<dyn std::error::Error>)` if a critical setup failure
///   occurs (such as failing to determine the cache path or create
///   the cache directory).
///
/// # Notes
///
/// The downloaded blob corresponds to the **FIDO Metadata Service v3**
/// dataset, which contains attestation metadata used to construct an
/// `AttestationCaList` compatible with the
/// [`start_attested_passkey_registration`](webauthn_rs::Webauthn::start_attested_passkey_registration)
/// workflow provided by the `webauthn-rs` crate.
///
/// Caching the blob at build time significantly reduces startup
/// latency and avoids repeated network requests during runtime.
///
/// # See Also
///
/// - [`download_blob`] – Downloads and stores the MDS blob.
/// - [`universal_user_path`] – Resolves the cross-platform cache path.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=data/ca_list.jwt");

    let cache_path = match universal_user_path() {
        Ok(path) => path,
        Err(e) => {
            log::error!("Failed to determine universal cache path: {e}");
            return Err(e.into());
        }
    };

    // Ensure directory exists
    if let Some(parent) = cache_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::error!("❌ Failed to create directory {}: {e}", parent.display());
                return Err(e.into());
            }
        }
    }

    println!("cargo:rerun-if-changed={}", cache_path.display());
    // println!("cargo:warning=[Build Info] cache_path is {cache_path:?}");
    log::debug!("Cache path is {cache_path:?}");
    // Avoid unnecessary downloads
    if cache_path.is_file() {
        //println!("cargo:warning=[Build Info] Using cached blob at {cache_path:?}");
        log::debug!("Using cached blob at {cache_path:?}");
        return Ok(());
    }

    //println!("cargo:warning=[Build Info] Wait a while , a fresh copy of FIDO MDS3 blob will be downloaded.");

    match download_blob(&cache_path) {
        Ok(_) => {
            //println!("cargo:warning=[Build Info] Blob cached successfully.");
            log::info!("Blob cached successfully.");
        }
        Err(e) => {
            log::error!("❌ Download failed: {e}. Runtime loader will fallback.");
            // println!(
            //     "cargo:warning=[Build Info] Download failed: {e}. Runtime loader will fallback."
            // );
        }
    }
    Ok(())
}

/// Universal user data path for downloading CA list
///
/// Platform-specific:
/// - Linux: ~/.local/share/fido_mds3_attestation_ca/ca_list.jwt
/// - macOS: ~/Library/Application Support/fido_mds3_attestation_ca/ca_list.jwt
/// - Windows: %LOCALAPPDATA%\fido_mds3_attestation_ca\ca_list.jwt
///
/// This function resolves a **cross-platform user data directory** where the
/// FIDO Metadata Service (MDS3) blob will be cached locally.
///
/// The directory is determined using the [`dirs`] crate, which provides a
/// platform-aware way to locate standard application data directories.
///
/// If the operating system specific data directory cannot be determined,
/// the function falls back to the **current working directory (`.`)** and
/// logs the event at the `debug` level.
///
/// Once the base directory is resolved, the function:
///
/// 1. Creates an application-specific subdirectory using the crate name.
/// 2. Ensures the directory exists (creating it if necessary).
/// 3. Returns the full path to the cached metadata blob file.
///
/// This path is used by the build script and runtime loader to store or
/// retrieve the **FIDO MDS3 JWT blob** used to construct an `AttestationCaList`.
///
/// # Returns
///
/// * `Ok(PathBuf)` — Full path to the cached `ca_list.jwt` file.
/// * `Err(std::io::Error)` — If the application directory cannot be created.
///
/// # Errors
///
/// An error is returned if:
///
/// - The application directory cannot be created.
/// - Filesystem permissions prevent directory creation.
///
/// # Notes
///
/// - The directory name is derived from the crate name using
///   `env!("CARGO_PKG_NAME")`.
/// - The function guarantees the parent directory exists before returning.
/// - The returned path may or may not already contain the metadata file.
///
/// # Logging
///
/// - `debug` — When resolving paths or creating directories.
/// - `error` — When directory creation fails.
///
/// # Example
///
/// ```rust,no_run
/// let path = universal_user_path()?;
/// println!("MDS cache path: {}", path.display());
/// # Ok::<(), std::io::Error>(())
/// ```
fn universal_user_path() -> Result<PathBuf, std::io::Error> {
    // 1. Try to find a valid data directory
    let base_dir = match dirs::data_local_dir().or_else(dirs::data_dir) {
        Some(dir) => dir,
        None => {
            log::debug!(
                "Could not determine OS data directory. Falling back to current directory ('.')"
            );
            PathBuf::from(".")
        }
    };

    // 2. Build the specific app subdirectory
    let crate_name = env!("CARGO_PKG_NAME");
    let app_dir = base_dir.join(crate_name);
    let full_path = app_dir.join(BLOB_FILE_NAME);

    // 3. Create the directory if it doesn't exist.
    if !app_dir.exists() {
        match fs::create_dir_all(&app_dir) {
            Ok(_) => log::debug!("Created application data directory at: {app_dir:?}"),
            Err(e) => {
                log::error!("Failed to create application directory {app_dir:?}: {e}");
                // In build.rs, we use cargo:warning to ensure it's visible during compilation
                // println!("cargo:warning=[Build Info] Error: Failed to create directory {app_dir:?}: {e}");
                return Err(e);
            }
        }
    }

    // 4. Return the full path to the file
    log::debug!("Universal path resolved to: {full_path:?}");

    Ok(full_path)
}

/// Downloads the FIDO Metadata Service (MDS3) blob and stores it locally.
///
/// This function retrieves the **FIDO MDS3 JWT metadata blob** from the
/// configured metadata service endpoint and writes it to the provided
/// target path.
///
/// The downloaded blob contains attestation metadata that can later be
/// parsed to construct an `AttestationCaList` compatible with
/// `webauthn-rs` attestation verification workflows.
///
/// # Download Process
///
/// The function performs the following steps:
///
/// 1. Creates an HTTP client using the [`ureq`] library with a timeout.
/// 2. Sends a GET request to the configured `BLOB_URL`.
/// 3. Handles HTTP errors such as rate limiting or server failures.
/// 4. Acquires a **filesystem lock** to prevent concurrent downloads.
/// 5. Streams the response body to a temporary file.
/// 6. Atomically renames the temporary file to the final target path.
/// 7. Removes the lock file after completion.
///
/// This ensures the downloaded blob is written safely without partial
/// writes or corruption.
///
/// # Concurrency Protection
///
/// To prevent multiple build processes from downloading the blob
/// simultaneously, a `.lock` file is used:
///
/// - If a lock file already exists and is **older than 5 minutes**,
///   it is considered stale and removed.
/// - A new lock file is then created before the download begins.
///
/// # Arguments
///
/// * `target` — Path where the downloaded blob will be stored.
///
/// # Returns
///
/// * `Ok(())` — The blob was successfully downloaded and stored.
/// * `Err(Box<dyn Error>)` — A network, HTTP, or filesystem error occurred.
///
/// # Errors
///
/// This function returns an error in the following situations:
///
/// - The metadata service responds with **HTTP 429 (rate limit exceeded)**.
/// - Any other HTTP error status is returned.
/// - Network failures (DNS, connection timeout, etc.).
/// - Failure to create or write to the target file.
/// - Failure to create the lock file.
///
/// # Atomic File Safety
///
/// To prevent corrupted downloads:
///
/// - The blob is first written to a temporary file (`.tmp`).
/// - After the download completes, the file is **atomically renamed**
///   to the final target path.
///
/// This ensures other processes never observe a partially written blob.
///
/// # Logging
///
/// - `debug` — Download start and lock maintenance.
/// - `info` — Successful download.
/// - `error` — Network failures, HTTP errors, or rate limiting.
///
/// # Notes
///
/// - The HTTP client timeout is set to **60 seconds**.
/// - The response body is streamed using an **8 KB buffer** to avoid
///   excessive memory usage.
/// - If the metadata service rate limits requests, users should retry
///   the build later.
///
/// # Example
///
/// ```rust,no_run
/// use std::path::PathBuf;
///
/// let path = PathBuf::from("ca_list.jwt");
/// download_blob(&path)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
fn download_blob(target: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .build();

    //println!("cargo:warning=[Build Info] Downloading FIDO MDS3 blob...");
    log::debug!("Downloading a fresh copy of FIDO MDS3 blob...");

    // Network errors or server errors may happen here
    let response = match agent.get(BLOB_URL).call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(429, _)) => {
            // FIDO Metadata Service rate limiting
            // println!(
            //     "cargo:warning=[Build Info] Error: FIDO Metadata Service rate limit reached (HTTP 429)."
            // );
            let error_429 =
                "FIDO Metadata Service rate limit reached (HTTP 429). Try again after some time.";
            log::error!("{error_429}");
            return Err(error_429.into());
        }
        Err(ureq::Error::Status(code, _)) => {
            // Other HTTP errors
            let http_error = format!("HTTP request failed with status code {code}");
            log::error!("{http_error}");
            //println!("cargo:warning=[Build Info] Error: {http_error}");
            return Err(http_error.into());
        }
        Err(ureq::Error::Transport(e)) => {
            // Network not available / DNS / connection errors
            let network_error = format!("Network error while downloading FIDO blob: {e}");
            log::error!("{network_error}");
            //println!("cargo:warning=[Build Info] Error: {network_error}");
            return Err(network_error.into());
        }
    };

    // Lock file to prevent concurrent downloads
    let lock_path = target.with_extension("lock");

    // Remove stale lock if older than 5 minutes
    if let Ok(meta) = fs::metadata(&lock_path) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap_or_default().as_secs() > 300 {
                //println!("cargo:warning=[Build Info] Removing stale download lock file.");
                log::debug!("cargo:warning=[Build Info] Removing stale download lock file.");
                let _ = fs::remove_file(&lock_path);
            }
        }
    }

    let _lock = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;

    // Write to temp file first
    let temp_path = target.with_extension("tmp");

    let mut reader = response.into_reader();
    let mut file = fs::File::create(&temp_path)?;

    let mut buffer = [0u8; 8192];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        file.write_all(&buffer[..n])?;
    }

    file.sync_all()?;

    // Atomic replace
    fs::rename(&temp_path, target)?;

    // Remove lock file
    let _ = fs::remove_file(lock_path);

    //println!("cargo:warning=[Build Info] Downloader invoked successfully!");
    log::info!("Downloaded successfully!");

    Ok(())
}
