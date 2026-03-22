//! CLI binary: `fido_mds3_attestation_ca`
//!
//! Command-line interface for interacting with the
//! `fido-mds3-attestation-ca` crate.
//!
//! This binary provides utilities for downloading and updating the
//! FIDO Metadata Service (MDS3) attestation blob locally.
//!
//! # Installation
//!
//! ```bash
//! cargo install fido_mds3_attestation_ca
//! ```
//!
//! # Usage
//!
//! Download the latest metadata blob:
//!
//! ```bash
//! fido_mds3_attestation_ca download
//! ```
//!
//! Enable logging for debugging:
//!
//! ```bash
//! RUST_LOG=info fido_mds3_attestation_ca download
//! ```
//!
//! The downloaded JWT metadata blob is stored in a platform-specific
//! user data directory resolved by [`universal_user_path`](fido_mds3_attestation_ca::universal_user_path).
//!
//! # References
//!
//! FIDO Metadata Service specification:  
//! <https://fidoalliance.org/metadata/>  
//!
//! Rust logging via `env_logger`:  
//! <https://docs.rs/env_logger/latest/env_logger/>

#![warn(unused_extern_crates)]
use fido_mds3_attestation_ca::logging;

#[cfg(feature = "cli")]
fn main() {
    use clap::Parser;
    use std::path::PathBuf;

    logging::init_logger();

    /// Command line interface definition for the CLI binary.
    ///
    /// Uses [`clap`](https://docs.rs/clap/latest/clap/) to parse commands
    /// and arguments provided by the user.
    #[derive(Parser)]
    #[command(name = env!("CARGO_PKG_NAME"))]
    #[command(about = "FIDO MDS3 Attestation CA List updater")]
    struct Cli {
        /// Available CLI subcommands.
        #[command(subcommand)]
        command: Commands,
    }

    /// Supported CLI commands.
    ///
    /// Currently only provides the ability to download the latest
    /// FIDO Metadata Service (MDS3) blob.
    #[derive(Parser)]
    enum Commands {
        /// Download the latest FIDO MDS3 attestation blob from the official FIDO website.
        ///
        /// The new blob will be available immediately on next application restart.
        /// To embed it permanently in the crate, recompile with `cargo build --release`.
        Download {
            /// Output file path (default: platform-specific user data directory)
            #[arg(short, long)]
            output: Option<PathBuf>,
        },
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Download { output } => {
            download::execute(output).unwrap_or_else(|e| {
                log::error!("❌ Network Error: {e}");
                std::process::exit(1);
            });
        }
    }
}

#[cfg(not(feature = "cli"))]
fn main() {
    logging::init_logger();
    log::error!("CLI feature not enabled. Rebuild with --features cli");
    std::process::exit(1);
}

#[cfg(feature = "cli")]
mod download {
    use fido_mds3_attestation_ca::constants::{BLOB_URL, EMBEDDED_JWT_PATH};
    use fido_mds3_attestation_ca::error::FidoMds3AttestationCaError;
    use fido_mds3_attestation_ca::universal_user_path;
    use indicatif::{ProgressBar, ProgressStyle};
    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    /// Execute the `download` CLI command.
    ///
    /// This function performs the following steps:
    ///
    /// 1. Resolves the target output path.
    /// 2. Sends an HTTP request to the official FIDO Metadata Service.
    /// 3. Streams the metadata blob to disk while displaying a progress bar.
    /// 4. Writes the file atomically using a temporary file and rename.
    /// 5. Prevents concurrent downloads using a lock file.
    ///
    /// If the request fails due to rate limiting or network errors,
    /// an appropriate [`FidoMds3AttestationCaError`] is returned.
    ///
    /// # Arguments
    ///
    /// * `output` — Optional custom output path for the downloaded JWT blob.
    ///   If not provided, a platform-specific path from
    ///   [`universal_user_path`] is used.
    ///
    /// # Errors
    ///
    /// Returns [`FidoMds3AttestationCaError`] if:
    ///
    /// * The network request fails
    /// * The FIDO server returns an error
    /// * Disk write operations fail
    /// * A concurrent download is detected
    ///
    /// # Example
    ///
    /// ```bash
    /// fido_mds3_attestation_ca download
    /// ```
    ///
    /// Or specify an output file:
    ///
    /// ```bash
    /// fido_mds3_attestation_ca download --output metadata.jwt
    /// ```
    pub fn execute(output: Option<PathBuf>) -> Result<(), FidoMds3AttestationCaError> {
        let target_path = match output {
            Some(path) => path,
            None => universal_user_path()?,
        };

        let jwt_path = target_path.with_extension("jwt");

        log::debug!("Step 1/2: Requesting FIDO MDS3 blob...");

        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            //.user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build();

        // Request the blob
        let response = match agent.get(BLOB_URL).call() {
            Ok(res) => res,

            // FIDO MDS server rate limiting
            Err(ureq::Error::Status(429, _)) => {
                log::error!("❌ Error 429: Rate-limited by FIDO. Please wait for few minutes.");
                return Err(FidoMds3AttestationCaError::RateLimitedError);
            }

            // Other HTTP errors returned by server
            Err(ureq::Error::Status(code, _)) => {
                log::error!("❌ Server returned HTTP error {code}. Download failed.");
                return Err(FidoMds3AttestationCaError::DownloadError(format!(
                    "HTTP error {code}"
                )));
            }

            // Network failures (offline, DNS failure, TLS failure, connection refused)
            Err(ureq::Error::Transport(e)) => {
                log::error!("❌ Network error while contacting FIDO server: {e}");
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }
        };

        // Get content length for the progress bar (if the server provides it)
        let total_size = response
            .header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        // --- PROGRESS BAR SETUP ---
        let pb = if total_size > 0 {
            ProgressBar::new(total_size)
        } else {
            ProgressBar::new_spinner()
        };

        // Added percent + speed for better CLI UX
        let style = match ProgressStyle::default_bar().template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] \
{bytes}/{total_bytes} ({percent}%) Download Speed:{bytes_per_sec} ETR:{eta}",
        ) {
            Ok(s) => s.progress_chars("#>-"),
            Err(e) => {
                log::error!("⚠ Progress bar style error: {e}");
                ProgressStyle::default_bar()
            }
        };

        pb.set_style(style);

        // --- STEP 2: STREAM TO DISK ---
        if let Some(parent) = jwt_path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    log::error!("❌ Failed to create directory {}: {e}", parent.display());
                    return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
                }
            }
        }

        // Lock file to prevent concurrent downloads
        let lock_path = jwt_path.with_extension("lock");

        // Remove stale lock (older than 5 minutes)
        if let Ok(meta) = std::fs::metadata(&lock_path) {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default().as_secs() > 300 {
                    let _ = std::fs::remove_file(&lock_path);
                }
            }
        }

        let lock = match std::fs::OpenOptions::new()
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

        // Write to temp file first
        let temp_path = jwt_path.with_extension("tmp");

        let mut file = match File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                log::error!("❌ Failed to create file {}: {e}", temp_path.display());
                let _ = std::fs::remove_file(&lock_path);
                drop(lock);
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }
        };

        let mut reader = response.into_reader();
        let mut buffer = [0; 8192]; // 8KB chunks
        let mut downloaded: u64 = 0;

        log::debug!("Step 2/2: Downloading to {}", jwt_path.display());

        loop {
            let n = match reader.read(&mut buffer) {
                Ok(n) => n,
                Err(e) => {
                    log::error!("❌ Failed to read from network stream: {e}");
                    let _ = std::fs::remove_file(&lock_path);
                    return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
                }
            };

            if n == 0 {
                break;
            }

            if let Err(e) = file.write_all(&buffer[..n]) {
                log::error!("❌ Failed to write to disk: {e}");
                let _ = std::fs::remove_file(&lock_path);
                return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
            }

            downloaded += n as u64;
            pb.set_position(downloaded);
        }

        if let Err(e) = file.sync_all() {
            log::error!("❌ Failed to sync file to disk: {e}");
            let _ = std::fs::remove_file(&lock_path);
            return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
        }

        // Atomic replace
        if let Err(e) = std::fs::rename(&temp_path, &jwt_path) {
            log::error!("❌ Failed to finalize download: {e}");
            let _ = std::fs::remove_file(&lock_path);
            return Err(FidoMds3AttestationCaError::DownloadError(e.to_string()));
        }

        let _ = std::fs::remove_file(lock_path);

        pb.finish_with_message("Download complete");

        // Copy downloaded JWT to embedded location (replaces old one)
        match fs::copy(&jwt_path, EMBEDDED_JWT_PATH) {
            Ok(_) => {
                if let Ok(file) = File::open(EMBEDDED_JWT_PATH) {
                    if let Err(e) = file.sync_all() {
                        log::warn!("⚠ Failed to sync file to disk: {e}");
                    }
                }
                log::debug!("✓ Updated embedded JWT: {EMBEDDED_JWT_PATH}");
                let is_embedded_enabled = cfg!(feature = "embedded");

                if is_embedded_enabled {
                    log::debug!("✅ Embedded feature is ACTIVE.");
                    log::debug!(
                        " → (Optional) To bake this update into the crate permanently, run:"
                    );
                    log::debug!("    cargo build --release");
                    log::debug!("⚠ NOTE: This will increase the final binary size.");
                } else {
                    log::debug!("ℹ️ Embedded feature is CURRENTLY DISABLED (Standard Mode).");
                    log::debug!(
                        " → (Optional) To enable permanent offline fallback, recompile with:"
                    );
                    log::debug!("   cargo build --release --features embedded");
                    log::debug!(
                        "⚠ NOTE: Enabling this feature will increase the final binary size."
                    );
                }
                log::debug!("    The newly downloaded blob will be loaded on next restart");
            }
            Err(e) => {
                log::error!("❌ Failed to copy JWT to embedded path: {e}");
                // Continue - download succeeded, just embedding update failed
            }
        }
        log::debug!(
            "✓ FIDO MDS3 blob saved to: {} And will be loaded on next restart.",
            jwt_path.display()
        );
        println!(
            "✓ FIDO MDS3 blob saved to: {} And will be loaded on next restart.",
            jwt_path.display()
        );

        Ok(())
    }
}
