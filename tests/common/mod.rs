//! Module to initialize logger for tests

// Import required crate.
use std::sync::Once;

static INIT: Once = Once::new();

/// Initializes the logger for integration and unit tests.
///
/// This function configures the [`env_logger`] backend so that log
/// messages emitted during tests (for example `log::debug!`,
/// `log::info!`, or `log::error!`) are visible when running `cargo test`.
///
/// The logger is initialized **only once** for the entire test process
/// using [`std::sync::Once`]. This avoids the common Rust logging error
/// where multiple tests attempt to initialize a global logger
/// simultaneously.
///
/// The logger is configured with `.is_test(true)` so that it integrates
/// correctly with Rust's test harness and ensures log output is captured
/// and displayed when tests fail or when `--nocapture` is used.
///
/// If initialization fails (for example, if another logger has already
/// been initialized), the error is printed to `stderr` but the tests
/// continue running.
///
/// # Behavior
///
/// - Ensures logging is initialized exactly once across all tests.
/// - Uses environment variables such as `RUST_LOG` to control log level.
/// - Prevents duplicate logger initialization errors.
///
/// # Example
///
/// Typical usage inside tests:
///
/// ```rust,no_run
/// use crate::tests::common::init_logger;
///
/// #[test]
/// fn my_test() {
///     init_logger();
///
///     log::debug!("Debug message from test");
/// }
/// ```
///
/// # Enabling Logs During Tests
///
/// By default Rust hides log output during tests. To see logs:
///
/// ```bash
/// RUST_LOG=debug cargo test -- --nocapture
/// ```
///
/// # Notes
///
/// - This helper should be called at the start of tests that rely on
///   logging output.
/// - Internally it uses [`Once`] to guarantee safe global initialization.
pub fn init_logger() {
    INIT.call_once(|| {
        if let Err(e) = env_logger::Builder::from_env(env_logger::Env::default())
            .is_test(true)
            .try_init()
        {
            eprintln!("Failed to initialize test logger: {e}");
        }
    });
}
