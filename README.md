# fido_mds3_attestation_ca

![Rust 1.85+](https://img.shields.io/badge/rust-1.85+-orange.svg)
[![Crates.io](https://img.shields.io/crates/v/fido_mds3_attestation_ca)](https://crates.io/crates/fido_mds3_attestation_ca)
[![GitHub](https://img.shields.io/badge/GitHub-181717?logo=github&logoColor=white)](https://github.com/GaneshJadhavOnGitHub/fido_mds3_attestation_ca)
[![Docs.rs](https://img.shields.io/badge/Docs.rs-000000?logo=docs.rs&logoColor=white)](https://docs.rs/fido_mds3_attestation_ca/latest)


A Rust library for extracting **attestation trust anchors** from the
FIDO Metadata Service (MDS3) for **WebAuthn authenticator verification**.

MSRV: 1.85 (2024 edition)

####   Crate Overview

This crate parses FIDO Metadata Service entries and builds a list of
**attestation root certificates (trust anchors)** that servers can use
to verify authenticator attestation during WebAuthn registration.

---

# Why `fido_mds3_attestation_ca`

During WebAuthn registration, authenticators may provide an **attestation
certificate chain** proving the authenticity of the hardware device.

To verify this chain, servers must trust a set of **attestation root
certificates**. These roots are published through the **FIDO Metadata
Service (MDS)**.

Managing these certificates manually is difficult because:

* The metadata contains **thousands of authenticator entries**
* Certificates are stored as **base64 encoded values**
* Authenticators may use **AAGUID (FIDO2)** or **AAID (U2F) identifiers**
* Not all entries contain valid attestation roots

`fido_mds3_attestation_ca` solves this problem by:

* Parsing the **FIDO MDS3 metadata**
* Extracting **valid attestation root certificates**
* Supporting both **FIDO2 and legacy U2F authenticators**
* Building a **deduplicated trust anchor list**

The resulting trust anchors can be used by WebAuthn servers
to verify authenticator attestation statements.


---

# Features

* Extract **attestation trust anchors** from FIDO MDS3 metadata
* Filter **FIDO certified authenticators**
* Supports both **AAGUID (FIDO2)** and **AAID (U2F)**
* Handles **invalid or malformed certificates safely**
* Logging support for production environments
* Simple API with minimal configuration
* Works **offline once metadata is downloaded**

---

# How it works - Metadata Strategy (Download → Build → Fallback)

The crate uses a **three-step strategy** for loading metadata:

1. **Download (recommended)**
   Use the provided CLI to download the latest **MDS3 BLOB**.

2. **Build**
   The library parses the BLOB and builds a list of **attestation trust anchors**.

3. **Fallback**
   If a local BLOB is not available, the crate falls back to an **embedded metadata snapshot** so applications can still run.

This approach provides:

* **Offline operation**
* **Predictable startup**
* **Safe fallback when metadata is unavailable**

---

# Important Usage Recommendation

Before using this crate in production:

1. **Download the latest metadata BLOB using the CLI binary**
2. **Restart your application** so the newly downloaded BLOB is loaded

Example workflow:

```
download metadata → restart application → build CA list
```

---

# Binary: Downloads Latest FIDO MDS3 BLOB

This crate provides a **CLI tool** that downloads the latest
FIDO Metadata Service BLOB.

### Install the binary

```
cargo install fido_mds3_attestation_ca
```

### Download the latest metadata

```
fido_mds3_attestation_ca download
```

This saves the latest **signed MDS3 metadata BLOB** locally.

---

# Metadata Refresh Recommendation

According to FIDO guidance, metadata does **not change frequently**.

Recommended approach:

* **Download the BLOB once per month**
* Cache the metadata locally
* Periodically refresh to obtain newly certified authenticators

Reference: https://fidoalliance.org/metadata/

---

# Usage (Library)

Add the crate to your `Cargo.toml`:

```
[dependencies]
fido_mds3_attestation_ca = "0.1.0-alpha"
```

---

# Example: Extract All Trust Anchors

```
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    let ca_list = build_ca_list(AttestationFilter::TrustAnchors)
        .expect("Failed to build CA list");

    println!("Total trust anchors: {}", ca_list.len());
}
```

This extracts **all valid attestation trust anchors** from metadata.

---

# Example: Extract Only FIDO Certified Trust Anchors

For security-critical applications, only FIDO Certified Trust Anchors can be extracted.

```
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    let ca_list = build_ca_list(
        AttestationFilter::FidoCertifiedTrustAnchorsOnly
    ).expect("Failed to build CA list");

    println!("FIDO certified anchors: {}", ca_list.len());
}
```

This returns only authenticators whose **latest status indicates FIDO Certified**.

---

# Integration with webauthn-rs

This crate is designed to integrate directly with:

```
webauthn-rs = "0.5.4"
```

The generated `AttestationCaList` can be passed directly to
`start_attested_passkey_registration`.

Example:

```
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

let ca_list = build_ca_list(AttestationFilter::TrustAnchors)
    .expect("Failed to build CA list");

webauthn.start_attested_passkey_registration(
    user_id,
    username,
    display_name,
    Some(exclude_credentials),
    ca_list,                   // Can be used here directly
    Some(ui_hint_authenticator_attachment),   
);
```

This allows WebAuthn servers to verify **authenticator attestation chains**
using trusted roots extracted from the FIDO Metadata Service.

---

# Logging

The crate supports structured logging via `env_logger`.

Example:

```
use fido_mds3_attestation_ca::logging;

fn main() {
    logging::init_logger();
}
```

---

# When should you use this crate?

This crate is useful if you are building:

* WebAuthn authentication servers
    * Passkey infrastructure
* FIDO2 verification services
* Security gateways validating authenticator devices
* Research tools analyzing FIDO authenticators

---

# Quick Links

🔗 Source code: [GitHub](https://github.com/GaneshJadhavOnGitHub/fido_mds3_attestation_ca)  
📦 Rust crate: [crates.io](https://crates.io/crates/fido_mds3_attestation_ca)  
📚 Documentation: [Docs.rs](https://docs.rs/fido_mds3_attestation_ca/latest)


# License

Licensed under either of

* MIT License
* Apache License 2.0

at your option.

---

# Contributing

Contributions, bug reports, and suggestions are welcome.

If you find a bug or want to propose an improvement:

1. Open an issue
2. Fork the repository
3. Create a feature branch
4. Submit a pull request

Please ensure:

* `cargo check` passes
* `cargo fmt` passes
* `cargo clippy` passes

---

# Related standards

* WebAuthn: https://www.w3.org/TR/webauthn/
* FIDO2: https://fidoalliance.org/specifications/
* FIDO Metadata Service: https://fidoalliance.org/metadata/
