//! Constants used in the crate.

/// URL to download Fido Mds3 blob
pub const BLOB_URL: &str = "https://mds3.fidoalliance.org/";

/// Blob file name to be used.
pub const BLOB_FILE_NAME: &str = "ca_list.jwt";

// --- Compile-time Embedding ---

#[cfg(feature = "embedded")]
/// The actual blob string baked into the binary.
pub const EMBEDDED_JWT: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/ca_list.jwt"));

#[cfg(not(feature = "embedded"))]
/// Empty string when the feature is disabled to save space.
pub const EMBEDDED_JWT: &str = "";

// --- Runtime Paths ---

/// Path for copying (runtime) after download.
/// NOTE: This remains available even if the 'embedded' feature is off,
/// as it is just a string path for download logic.
pub const EMBEDDED_JWT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/ca_list.jwt");
