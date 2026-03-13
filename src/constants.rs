//! Constants used in the crate.
/// URL to download Fido Mds3 blob
pub const BLOB_URL: &str = "https://mds3.fidoalliance.org/";
/// Embedded JWT Path
pub const EMBEDDED_JWT: &str = include_str!("../data/ca_list.jwt");
/// Blob file name to be used.
pub const BLOB_FILE_NAME: &str = "ca_list.jwt";
