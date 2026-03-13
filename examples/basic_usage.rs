//! Example: Using fido_mds3_attestation_ca library
//!
//! This example demonstrates how to use the
//! `fido_mds3_attestation_ca` library to build attestation
//! certificate authority (CA) lists from the FIDO Metadata
//! Service (MDS3).
//!
//! The example shows two common usage scenarios:
//!
//! 1. **Retrieve attestation trust anchors**
//!    - Includes root certificates for authenticators that provide
//!      valid attestation root certificates in the FIDO Metadata Service.
//!
//! 2. **Retrieve only FIDO-certified attestation trust anchors**
//!    - Filters authenticators whose latest status indicates
//!      official FIDO Alliance certification.
//!
//! The returned [`AttestationCaList`] can be used by WebAuthn
//! servers or authentication systems to verify authenticator
//! attestation statements.
//!
//! # Steps Performed
//!
//! 1. Initialize the crate logger.
//! 2. Select an [`AttestationFilter`] variant.
//! 3. Call [`build_ca_list`] to generate the CA list.
//! 4. Handle possible errors returned by the library.
//! 5. Use the resulting trust anchors for verification or inspection.
//!
//! # Running the Example
//!
//! ```bash
//! cargo run --example basic_usage
//! ```
//!
//! # References
//!
//! - FIDO Metadata Service: https://fidoalliance.org/metadata/
//! - WebAuthn specification (attestation model): https://www.w3.org/TR/webauthn/
//! - Rust logging with `env_logger`: https://docs.rs/env_logger/latest/env_logger/

use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::logging;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    // Initialize logger.
    logging::init_logger();

    // Example 1 Filter :: TrustAnchors

    //Initialise required filter.
    let trust_anchors_filter = AttestationFilter::TrustAnchors;

    //Call build function by passing filter variant as an argument.
    let trust_anchors_list = match build_ca_list(trust_anchors_filter) {
        Ok(list) => list,
        Err(e) => {
            log::error!("Error: Failed to build CA list: {e}");
            eprintln!("Error: Failed to build CA list: {e}");
            return;
        }
    };

    // Logging for production.
    log::info!(
        "Successfully built CA list with {} entries",
        trust_anchors_list.len()
    );

    println!("Trust Anchors: {}", trust_anchors_list.len());

    //------------------------------------------------------------------

    // Example 2 Filter :: FidoCertifiedTrustAnchorsOnly

    //Initialise required filter.
    let fido_certified_trust_anchors_filter = AttestationFilter::FidoCertifiedTrustAnchorsOnly;

    //Call build function by passing filter variant as an argument.
    let fido_certified_trust_anchors_list = match build_ca_list(fido_certified_trust_anchors_filter)
    {
        Ok(list) => list,
        Err(e) => {
            log::error!("Error: Failed to build CA list: {e}");
            eprintln!("Error: Failed to build CA list: {e}");
            return;
        }
    };

    // Logging for production.
    log::info!(
        "Successfully built CA list with {} entries",
        fido_certified_trust_anchors_list.len()
    );

    println!(
        "FIDO Certified Trust Anchors: {}",
        fido_certified_trust_anchors_list.len()
    );
}
