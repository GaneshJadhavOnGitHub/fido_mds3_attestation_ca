# Changelog

All notable changes to this carte will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-03-17

### Added
- Initial release
- Parse FIDO MDS3 JWT blob in pure Rust
- Extract attestation trust anchors for FIDO2 (AAGUID) and U2F (AAID) authenticators
- Build deduplicated CA list from metadata entries
- CLI binary `fido_mds3_attestation_ca` for downloading latest metadata BLOB
- `build_ca_list()` API with internal caching
- `AttestationFilter` for filtering trust anchors (all or FIDO-certified only)
- Embedded metadata fallback for offline operation
- Integration support for `webauthn-rs` crate
- Structured logging support via `env_logger` crate

## [0.1.1-alpha] - 2025-03-17

- Fixed rust doc generation issue


## [0.1.1-alpha.1] - 2025-03-18

- Added missing rust doc comments
- Fixed few cargo clippy warnings occurred when "Doc" Lints enabled
- Added more keywords in Cargo.toml
- Added new description in Cargo.toml
- Removed trailing blank spaces from URL's in README.md 

## [0.1.1-alpha.2] - 2025-03-18

- Minor corrections in README.md

## [0.1.1-alpha.3] - 2026-03-19

### Added
- **New Feature Flag:** Added `embedded` feature to `Cargo.toml`. This allows users to opt-in to the large embedded FIDO MDS3 snapshot.
- **Strategic Fallback:** Implemented a "Lean by Default" strategy. The crate now defaults to a minimal footprint and only includes the embedded data if explicitly requested.
- **Enhanced Documentation:** Added `Feature Gating` sections to `rustdoc` for `load_jwt()` and `embedded_ca_list()` to explain behavior when the `embedded` feature is disabled.
- **Debug Logging:** Added specific log statements to identify if the crate is running in "Lean" mode or using the "Embedded" fallback.

### Changed
- **Binary Size Optimization:** Reduced the default `.rlib` size from **~22 MB** to **~830 KB** (a 96% reduction) by feature-gating the embedded JWT constant.
- **Lazy Initialization:** Updated `EMBEDDED_PARSED` to return an empty `ParsedBlob` when the `embedded` feature is disabled, preventing unnecessary memory allocation and parsing overhead.
- **Test Suite Updates:** Refactored `lib_tests.rs` to be feature-aware, ensuring tests pass correctly in both "Standard" and "Embedded" build modes.

### Fixed
- **Compiler Warnings:** Resolved `unused_import` warnings for `EMBEDDED_JWT` and related test dependencies when building without the `embedded` feature.


## [0.1.1-alpha.4] - 2026-03-20

- Improved rustdoc comments for library and loader functions.
- Improved compile time log messages for build.rs and cli tool.
- Improved README.md
