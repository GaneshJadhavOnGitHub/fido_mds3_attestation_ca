//! Logging utilities for the crate.
//!
//! This module provides a helper function to initialize structured logging
//! using the `env_logger` backend. The logger configuration is derived from
//! environment variables (for example `RUST_LOG`), which allows users to
//! control log verbosity without recompiling the application.

#![allow(clippy::needless_doctest_main)]

/// Initializes the global logger for the crate.
///
/// This function configures logging using the `env_logger` builder with
/// environment-based configuration. It reads the `RUST_LOG` environment
/// variable to determine the desired log level and filtering rules.
///
/// # Behavior
///
/// - If the logger is successfully initialized, log messages from the crate
///   and its dependencies will be emitted according to the configured level.
/// - If the logger has already been initialized (for example by another
///   library or test), initialization will fail gracefully and an error
///   message will be printed to standard error.
///
/// # Example
///
/// ```rust
/// use fido_mds3_attestation_ca::logging::init_logger;
///
/// fn main() {
///     init_logger();
///     log::info!("Application started");
/// }
/// ```
///
/// To enable logging at runtime:
///
/// ```bash
/// RUST_LOG=info cargo run
/// ```
///
/// # Notes
///
/// This function is safe to call multiple times. Only the first successful
/// initialization takes effect; subsequent attempts will be ignored and
/// reported via `stderr`.
pub fn init_logger() {
    if let Err(e) = env_logger::Builder::from_env(env_logger::Env::default()).try_init() {
        eprintln!("⚠️  Failed to initialize logger: {e}");
    }
}
