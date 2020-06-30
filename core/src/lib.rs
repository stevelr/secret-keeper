//! # Secret-Keeper
//!
//! Envelope encryption with strong cryptography and key management.
//! A SecretKeeper encrypts a data encryption key (DEK) with a key-encryption-key (KEK),
//! returning a [`WrappedKey`](struct.WrappedKey.html).
//! This crate (and sub-crates) implement several SecretKeepers,
//! plus three content encryption ciphers:
//! - XCha20Cha20-Poly1305 with AEAD
//! - AES-GCM (256-bit)
//! - and a compressing cipher that combines LZ4 with XChaCha20-Poly1305
//!
//! The APIs in this crate are intended to
//! provide good security practices while minimizing opportunities
//! for unintentional developer errors that could reduce the security.
//! One such principle is that encryption keys are always stored encrypted at rest.
//!
//! Some SecretKeeper implementations have already been developed.
//! If you create a new one, please send me a link and I'll link to it from here.
//!
//! - __Env__ generates a key from a passphrase stored in an
//! environment variable, using PBKDF2+HMAC+SHA256+SALT.
//! [EnvKeeper](keepers/env/struct.EnvKeeper.html)
//!
//! - __Prompt__ prompts the user at a terminal for a passphrase.
//! The KEK is generated from the passphrase using PBKDF2+HMAC+SHA256+SALT.
//! Requires the `secret-keeper-prompt` crate.
//! [PromptKeeper](../secret_keeper_prompt/struct.PromptKeeper.html)
//!
//! - __Hashivault__ Using Vault's Transit engine, the HashivaultKeeper
//! can create keys (key-encryption-keys) with a variety of encryption algorithms, including
//! `aes-gcm-256`, `ed25519`, and several others). A DEK is encrypted or decrypted by the Vault,
//! using the KEK managed-by and stored-on the Vault.
//! [Hashivault](../secret_keeper_hashivault/struct.HashivaultKeeper.html)
//!
//! - __CloudKMS__ The CloudKmsKeeper uses keys in Google CloudKMS service.
//!
//! - __1Password__ (linux/mac only). 1Password is included in the example directory to show how
//! external programs can be used with EnvKeeper and a shell script; no additionl rust code
//! is required. Uses the free 1password
//! [`op cli tool`](https://support.1password.com/command-line-getting-started/),
//!
//! ## Implementation notes
//!
//! Crypto algorithms used are implemented by other packages, notably
//! [RustCrypto](https://github.com/rustcrypto/), a pure-rust implemenation.
//!
//! LZ4 compression is a pure rust implementation by [`lz_fear`](https://crates.io/crates/lz-fear).
//!
//! The concept for this library is based on the google cloud secret-keeper library
//!
//! ## Status
//!
//! This is a new crate and it should be considered alpha quality.
//!
//! Additional SecretKeeper implementations are planned. If you create any, please let me know and
//! I'll link to it from here.
//!
//! The core secret-keeper library compiles into wasm without error,
//! but I haven't tested it in a browser yet.
//!

// Catch documentation errors caused by code changes.
#[deny(intra_doc_link_resolution_failure)]
#[deny(missing_docs)]
//
pub mod ciphers;
pub mod error;
pub mod keepers;
pub mod rand;
pub mod util;
use serde::{Deserialize, Serialize};

/// A WrappedKey provides a way to store and communicate encrypted-encryption keys.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WrappedKey {
    /// `key_enc` holds a string representation of an encrypted key
    /// The specific format may vary depending on the SecretKeeper, but it is usually some
    /// recognizable prefix followed by a base-64-encoded key
    pub key_enc: String,
    /// `key_uri` is the identifier for the wrapping method and/or the key used. The scheme of the
    /// uri determines the keeper type. For example, `hashivault://abc` is a key named 'abc' on a
    /// hashicorp vault.
    pub key_uri: String,
    /// `ident` is any optional identifier for the key. It might be a fingerprint, a uuid,
    /// or an email address of the owner of a public (asymmetric) key.
    pub ident: Option<String>,
}

#[macro_use]
WithAuthTag!(AuthTag, 16);

impl AuthTag {
    pub fn get_slice(&self) -> &[u8] {
        &self.0
    }
}
