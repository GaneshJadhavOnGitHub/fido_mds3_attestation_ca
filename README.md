# fido_mds3_attestation_ca

![Rust 1.85+](https://img.shields.io/badge/rust-1.85+-orange.svg)
[![Crates.io](https://img.shields.io/crates/v/fido_mds3_attestation_ca)](https://crates.io/crates/fido_mds3_attestation_ca)
[![GitHub](https://img.shields.io/badge/GitHub-181717?logo=github&logoColor=white)](https://github.com/GaneshJadhavOnGitHub/fido_mds3_attestation_ca)
[![Docs.rs](https://img.shields.io/badge/Docs.rs-000000?logo=docs.rs&logoColor=white)](https://docs.rs/fido_mds3_attestation_ca/latest)


A Rust library for extracting **attestation trust anchors** from the
FIDO Metadata Service (MDS3) for **WebAuthn authenticator verification**.

Compatible with the `webauthn-rs` crate — returns `webauthn_rs::prelude::AttestationCaList` directly.

MSRV: 1.85 (2024 edition)

####   Crate Overview

This crate parses FIDO Metadata Service entries and builds a list of
**attestation root certificates (trust anchors)** that servers can use
to verify authenticator attestation during WebAuthn registration.

---

## Why `fido_mds3_attestation_ca`

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
## Features


* Extract **attestation trust anchors** from FIDO MDS3 metadata
* Filter **FIDO certified authenticators**
* Supports both **AAGUID (FIDO2)** and **AAID (U2F)**
* Handles **invalid or malformed certificates safely**
* **Logging support** for production environments
* **Easy to use** with minimal configuration


---


## How it works - Metadata Strategy (Download → Build → Fallback)

The crate uses a **three-step strategy** for loading metadata:

1. **Download (Recommended)** - 
   Use the provided CLI tool to download the latest **MDS3 BLOB**.

2. **Build -**
   The library parses the BLOB and builds a list of **attestation trust anchors** and caches this list for subsequent calls.

3. **Fallback -**
   If a local BLOB is not available, the crate falls back to an **embedded metadata snapshot** so applications can still run.

This approach provides:

* **Reliable startup**
* **Better performance**
* **Safe fallback when metadata is unavailable**

---

## Important Usage Recommendation

To use this crate in production:

1. **Download the latest metadata BLOB** using the CLI tool.
2. **Restart your application** to load the newly downloaded BLOB.
3. *(Optional)* **Recompile with `cargo build --release`** to embed the new blob permanently in the crate.


💡 **Pro tip:**  Call `build_ca_list()` once at startup, before your server begins listening. 
This "warms up" the cache so attestation trust anchors are ready for all subsequent requests.

Example workflow:

```
download metadata → restart application → build CA list (at startup)
```

---

## Binary: To download Latest FIDO MDS3 BLOB

This crate provides a **CLI tool** that downloads the latest
FIDO Metadata Service BLOB from the official FIDO website.

### Install the binary

```bash
cargo install fido_mds3_attestation_ca
```

### Download the latest metadata

```bash
fido_mds3_attestation_ca download
```
This saves the latest **signed MDS3 metadata BLOB** locally.


### View download help

```bash
fido_mds3_attestation_ca download --help
```

### Run with logging

```bash
RUST_LOG=info fido_mds3_attestation_ca download
```

---

## Metadata Refresh Recommendation by FIDO

According to FIDO guidance, metadata BLOB **does not change frequently**.

**Recommended approach:**

- **Download fresh metadata once per month** to pick up newly certified authenticators.
- **Cache the metadata locally** for best performance.


Reference: https://fidoalliance.org/metadata/

---

## Usage (Library)

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
fido_mds3_attestation_ca = "0.1.1-alpha.2"
```

---

## Example: Extract All Trust Anchors

```rust
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    let ca_list = build_ca_list(AttestationFilter::TrustAnchors)
        .expect("Failed to build CA list");

    println!("Total number of trust anchors: {}", ca_list.len());
}
```

This extracts **all valid attestation trust anchors** from metadata.

---

## Example: Extract Only FIDO Certified Trust Anchors

For security-critical applications, only FIDO Certified Trust Anchors can be extracted.

```rust
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    let ca_list = build_ca_list(
        AttestationFilter::FidoCertifiedTrustAnchorsOnly
    ).expect("Failed to build CA list");

    println!("Total number of FIDO certified anchors: {}", ca_list.len());
}
```

This returns only authenticators whose **latest status indicates FIDO Certified**.

---

## Integration with webauthn-rs

This crate is compatible with:

```toml
webauthn-rs = "0.5.4"
```

The generated `AttestationCaList` can be passed directly to
`start_attested_passkey_registration` function.

Example:

```rust
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

let attestation_ca_list = build_ca_list(AttestationFilter::TrustAnchors)
    .expect("Failed to build CA list");

webauthn.start_attested_passkey_registration(
    user_id,
    username,
    display_name,
    Some(exclude_credentials),
    attestation_ca_list,                // **Can be used here directly**
    Some(ui_hint_authenticator_attachment),   
);
```

This allows WebAuthn servers to verify **authenticator attestation chains**
using trusted roots extracted from the FIDO Metadata Service.

---

## Logging

The crate supports structured logging via `env_logger`.

Just initialize ```env_logger``` in your application.

---

## When should you use this crate?

This crate is useful if you are building:

* WebAuthn authentication servers
* Passkey infrastructure
* FIDO2 verification services
* Security gateways validating authenticator devices

---

## Quick Links

🔗 Source code: [GitHub](https://github.com/GaneshJadhavOnGitHub/fido_mds3_attestation_ca)

📦 Rust crate: [crates.io](https://crates.io/crates/fido_mds3_attestation_ca)

📚 Documentation: [Docs.rs](https://docs.rs/fido_mds3_attestation_ca/latest)


## License

Licensed under either of

* MIT License
* Apache License 2.0

at your option.

---

## Contributing

Contributions, bug reports, and suggestions are welcome.

Please open an issue first for significant changes.

---

## Related standards

* WebAuthn: https://www.w3.org/TR/webauthn/
* FIDO2: https://fidoalliance.org/specifications/
* FIDO Metadata Service: https://fidoalliance.org/metadata/
