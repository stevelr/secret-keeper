//! SecretKeeper definitions and implementations.
//! This crate contains a small number of built-in SecretKeepers that are automatically
//! registered and discoverable with SecretKeeper::for_uri().
//! Any SecretKeeper that is not pure rust, or that would prevent secret-keeper core from
//! compiling to wasm, should be implemented as a separate optional crate. Additionally,
//! SecretKeepers that depend on external services (such as a Google Cloud or AWS)
//! or hardware, should be packaged separately from the core library.
pub mod env;
pub mod hkdf;

mod secretkeeper;
pub use secretkeeper::{Create, SecretKeeper};
