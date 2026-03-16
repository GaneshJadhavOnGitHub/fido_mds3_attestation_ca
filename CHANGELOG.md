# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2025-03-16

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