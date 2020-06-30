//! Crate error handling

use chacha20poly1305::aead;

use getrandom;
pub use std::result::Result;
use strum;
use thiserror::Error as ThisError;
pub type GenericError = Box<dyn std::error::Error + Send + Sync>;

/// Error enum that rolls-up all error messages in this crate
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Error: {0}")]
    GenericError(#[from] GenericError),

    #[error("IO error: {0}")]
    IOError(std::io::Error),

    #[error("Format error: {0}")]
    FmtError(#[from] std::fmt::Error),

    //#[error("Async IO error: {0}")]
    //AsyncIOError(#[from] futures_io::Error),
    #[error("invalid ip address: {0}")]
    IPAddrParseError(#[from] std::net::AddrParseError),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Missing environment setting: {0}")]
    MissingEnv(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Unknown crypto error")]
    UnknownCryptoError(),

    #[error("Invalid key string: {0}")]
    KeyEncodingError(#[from] bech32::Error),

    #[error("File IO error: {0}")]
    SaveError(std::io::Error),

    #[error("File Read error: {0}")]
    ReadError(std::io::Error),

    #[error("function not applicable")]
    NotApplicableError(),

    #[error("not implemented")]
    NotImplementedError(),

    #[error("Random generation error: {0}")]
    Random(String),

    #[error("Error: {0}")]
    OtherError(String),

    #[error("Keeper not found: {0}")]
    KeeperNotFound(String),

    #[error("Scan error at {0}: {1}")]
    ScanError(String, &'static str),

    #[error("(De)Serialization error {0}")]
    SerializationError(String),

    #[error("AEAD crypto error {0}")]
    AeadError(aead::Error),

    #[error("Cast error: does not implement trait {0}")]
    CastError(String),

    #[error("urlencoding format error: {0}")]
    UrlEncodingError(#[from] serde_urlencoded::ser::Error),

    #[error("Invalid enum value {0}")]
    ParseError(#[from] strum::ParseError),

    #[error("encoding error {0}")]
    UTF8EncodingError(String),
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Error {
        Error::UTF8EncodingError(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IOError(e)
    }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Error {
        Error::AeadError(e)
    }
}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Error {
        Error::Random(String::from("out of entropy"))
    }
}

#[cfg(test)]
impl From<Box<bincode::ErrorKind>> for Error {
    fn from(e: Box<bincode::ErrorKind>) -> Error {
        Error::SerializationError(e.to_string())
    }
}
