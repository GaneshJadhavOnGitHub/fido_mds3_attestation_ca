//! Constants used in the crate.
/// URL to download Fido Mds3 blob
pub const BLOB_URL: &str = "https://mds3.fidoalliance.org/";

/// Path to store JWT for compile-time embedding.
pub const EMBEDDED_JWT: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/ca_list.jwt"));

/// Path for copying (runtime) after download.
pub const EMBEDDED_JWT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/ca_list.jwt");

/// Blob file name to be used.
pub const BLOB_FILE_NAME: &str = "ca_list.jwt";
