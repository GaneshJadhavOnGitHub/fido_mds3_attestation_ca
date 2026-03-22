# fido_mds3_attestation_ca

[![Rust](https://img.shields.io/badge/rust-1.88.0-orange)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-blue)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
[![Crates.io](https://img.shields.io/crates/v/fido_mds3_attestation_ca)](https://crates.io/crates/fido_mds3_attestation_ca)
[![GitHub](https://img.shields.io/badge/GitHub-181717?logo=github&logoColor=white)](https://github.com/GaneshJadhavOnGitHub/fido_mds3_attestation_ca)
[![Docs.rs](https://img.shields.io/badge/Docs.rs-000000?logo=docs.rs&logoColor=white)](https://docs.rs/fido_mds3_attestation_ca/latest)


A Rust library for extracting **attestation trust anchors** from the
FIDO Metadata Service (MDS3) for **WebAuthn authenticator verification**.

Compatible with the `webauthn-rs` crate — returns `webauthn_rs::prelude::AttestationCaList` directly.


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

* The metadata contains **hundreds of authenticator entries**
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
* **Lean by default:** Optional embedded fallback to keep backend binaries small
* **Easy to use** with minimal configuration
* **Built-in CLI Tool** : Includes a command-line utility to easily download and update the latest **FIDO MDS3 metadata BLOB** locally


---


---

## How it works - Metadata Strategy (Download → Initialize → Fallback)

The crate uses a **three-step strategy** for loading metadata:

1. **Download (Recommended)** – 
   Everytime use the provided CLI tool to download the latest **MDS3 BLOB**.

2. **Initialize** – 
   The library parses the BLOB, builds a list of **attestation trust anchors**, and caches this list for subsequent calls.

3. **Fallback** – 
   If download fails or a local BLOB is unavailable, the crate checks for an **embedded metadata snapshot**. 
   **Note:** This fallback is only active if the `embedded` feature is enabled during compilation.

### 📦 Choosing your Build Strategy

To support high-performance backend environments, this crate is **Lean by Default**.

* **Standard Mode (Default):** Optimized for cloud backends, Docker containers, and serverless environments. It excludes the large embedded fallback to keep your binary size minimal.

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
fido_mds3_attestation_ca = "0.1.1-rc.2"
```

* **Embedded Mode (Optional):** If your application runs in an air-gapped or offline environment where downloading metadata is restricted, you can choose to bake the metadata snapshot directly into your binary to serve as a permanent fallback. But this will increase the size of your binary.

To enable the permanent offline fallback, add the `embedded` feature in your `Cargo.toml`:

```toml
[dependencies]
fido_mds3_attestation_ca = { version = "0.1.1-rc.2", features = ["embedded"] }
```


---

## Important Usage Recommendation

To use this crate in production:

1. **Download the latest metadata BLOB** using the CLI tool.
2. **Restart your application** to load the newly downloaded BLOB.
3. *(Optional)* **Recompile with `cargo build --release --features embedded`** to embed the new blob permanently in the crate.

> **Note:** The "Fallback" step and compile-time embedding  work only if the **`embedded` feature is enabled** in your `Cargo.toml` or via the command line. In **Standard Mode (Default)**, the crate remains lightweight and will not include the fallback snapshot, as it increases the size of the binary.


💡 **Pro tip:**  Call `build_ca_list()` once at startup, before your server begins listening. 
This "warms up" the cache so attestation trust anchors are ready for all subsequent requests.

Example workflow:

```
download metadata → restart application → build CA list (at startup)
```

This approach provides:

* **Reliable startup**
* **Better performance**
* **Safe fallback when metadata is unavailable**

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


## FIDO Metadata Compliance

This crate is designed to follow the FIDO Alliance Metadata Service (MDS) guidelines for performance.

### 1. Automatic Local Caching

To minimize network latency and external dependencies, this crate automatically caches the metadata BLOB on your local system, as recommended by FIDO.

### 2. Staying Up-to-Date (Monthly Refresh)

FIDO recommends refreshing the metadata once per month to include newly certified authenticators. To follow this recommendation using our tool:

#### Step 1: Download

Run the CLI binary to fetch the latest BLOB from FIDO:

```bash
fido_mds3_attestation_ca download
```
    
#### Step 2: Reload
    
Restart your application. The crate will automatically detect the fresh BLOB in your local cache and load it during initialization.

Reference: https://fidoalliance.org/metadata/

---

## Usage (Library)

### Standard Mode (Default)

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
fido_mds3_attestation_ca = "0.1.1-rc.2"
```
### Embedded Mode (Optional)

Add the crate to your `Cargo.toml` with `features = ["embedded"]`

```toml
[dependencies]
fido_mds3_attestation_ca = { version = "0.1.1-rc.2", features = ["embedded"] }
```

---

## Crate Features

| Feature | Default | Description |
| :--- | :---: | :--- |
| `cli` | **Yes** | The command-line tool for downloading the MDS3 BLOB. |
| `embedded` | No | Bakes the large FIDO metadata snapshot into the crate as a fallback. |

---

## Example: Extract All Trust Anchors

```rust
use fido_mds3_attestation_ca::build_ca_list;
use fido_mds3_attestation_ca::types::AttestationFilter;

fn main() {
    let attestation_ca_list = build_ca_list(AttestationFilter::TrustAnchors)
        .expect("Failed to build CA list");

    println!("Total number of trust anchors: {}", attestation_ca_list.len());
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
    let attestation_ca_list = build_ca_list(
        AttestationFilter::FidoCertifiedTrustAnchorsOnly
    ).expect("Failed to build CA list");

    println!("Total number of FIDO certified anchors: {}", attestation_ca_list.len());
}
```

This returns only authenticators whose **latest status indicates FIDO Certified**.

---

## Integration with webauthn-rs

This crate is compatible with:

```toml
webauthn-rs = "0.6.0-dev"
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
