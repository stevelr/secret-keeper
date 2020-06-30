//! Encryption ciphers

mod cipher;
pub use cipher::{Cipher, CipherKind, CompressingCipher, Import};

pub mod macs;

pub mod xchacha20;
pub mod xchacha20_comp;

mod aesgcm;
pub use aesgcm::aesgcm256;

mod test_ciphers;
mod test_xchacha20_comp;
