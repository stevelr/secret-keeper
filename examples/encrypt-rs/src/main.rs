//!
//! File encryption using SecretKeeper
//! - https://github.com/stevelr/encrypt-rs
//!
//! SecretKeeper
//! - [Documentation](https://docs.rs/secret-keeper)
//! - [Repository](https://github.com/stevelr/secret-keeper)
//!
//! # Syntax:
//!
//! ```
//!  # Encrypt file
//!  $ encrypt enc -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE
//!
//!  # Decrypt file
//!  $ encrypt dec -o OUT [ -k KEEPER ] [ -c CIPHER ] FILE
//!
//!  # View key envelope
//!  $ encrypt key view   [ -k KEEPER ] FILE
//! ```
//!
//! # Keeper uris
//!
//! If secret keeper uri is not specified, default `env:` is used.
//!
//! Secret keepers:
//! - `env:`  - passphrase for deriving key is in environment var VAULT_PASSWORD
//! - `env:VARNAME` - passphrase for deriving key is in environment variable VARNAME
//! - `prompt:` - user will be prompted on terminal for passphrase for deriving key
//! - `hashivault:...`        - key-encrypting-key is on hashivault transit server.
//!   See [hashivault keeper](https://docs.rs/secret-keeper-hashivault) doc for url syntax
//! - as more SecretKeepers are implemented, more options become available.
//!

// ```
// Generates encrypted file with the following format:
// -------------------------------------
//  Header   (64 bytes)
//      Offset   Size  Desc
//       0-17     18    Magic string
//       18       1     Format version
//       19       1     CipherKind
//       20-23    4     Envelope size
//       24-47    24    Nonce
//       48-63    16    Tag
// -------------------------------------
//  Key Envelope (variable len)
//      WrappedKey {...}
// -------------------------------------
//  Encrypted file body
// -------------------------------------
// ```

use clap::Clap;
mod options;
use options::{
    Command::{Decrypt, Encrypt, Key},
    DecryptOptions, EncryptOptions,
    KeyCommand::View,
    Main, ViewKeyOptions,
};
use secret_keeper::{
    ciphers::{xchacha20_comp::TAGBYTES, CipherKind},
    keepers::SecretKeeper,
    rand,
    util::uninitialized_bytes,
    WrappedKey,
};
#[cfg(feature = "cloudkms")]
use secret_keeper_cloudkms::CloudKmsKeeper;
#[cfg(feature = "hashivault")]
use secret_keeper_hashivault::HashivaultKeeper;
#[cfg(feature = "prompt")]
use secret_keeper_prompt::PromptKeeper;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

const MAGIC: &[u8] = b"keeper_demo";
const MAGIC_MAX_LEN: usize = 18;
const FORMAT_VERSION: u8 = 1;
const FILE_NONCEBYTES: usize = 24;
const HEADER_LEN: usize = 24 + FILE_NONCEBYTES + TAGBYTES; // size of serialied EncHeader

#[derive(Serialize, Deserialize, Debug)]
struct EncHeader {
    magic: [u8; MAGIC_MAX_LEN],
    format_version: u8,
    cipher_kind: CipherKind,
    envelope_size: u32,
    nonce: [u8; FILE_NONCEBYTES],
    tag: [u8; TAGBYTES],
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e.to_string());
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    // register keeper plugins
    #[cfg(feature = "hashivault")]
    HashivaultKeeper::new_default().await?.register().await?;
    #[cfg(feature = "prompt")]
    PromptKeeper::new_default().register().await?;
    #[cfg(feature = "cloudkms")]
    CloudKmsKeeper::new_default().await?.register().await?;

    let args = Main::parse();
    match args.command {
        Encrypt(opt) => encrypt_file(&opt).await,
        Decrypt(opt) => decrypt_file(&opt).await,
        Key(k) => match k.command {
            View(opt) => view_key(&opt).await,
        },
    }
}

#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("{0}")]
    IOError(std::io::Error),

    #[error("{0}")]
    LibError(#[from] secret_keeper::error::Error),

    #[error("Corrupt file - serialization error {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("Not a valid encrypted file {0}")]
    InvalidFile(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e)
    }
}

/// Encrypt file.
pub(crate) async fn encrypt_file(opt: &EncryptOptions) -> Result<(), Error> {
    let keeper = SecretKeeper::for_uri(&opt.keeper_uri.clone()).await?;
    // create file nonce and use it to seed cipher key
    let mut file_nonce = [0u8; FILE_NONCEBYTES];
    rand::fill_buf(&mut file_nonce)?;
    let cipher = keeper
        .init_cipher(opt.cipher.clone(), &file_nonce, None)
        .await?;

    // generate envelope and serialize
    let envelope = cipher.export(&opt.keeper_uri, &file_nonce, &keeper).await?;
    let key_buf = bincode::serialize(&envelope)?;

    // read file and encrypt, saving tag for header
    let (buf, file_tag, _) = cipher.seal_file(&opt.file, None).await?;

    // generate fixed header
    let mut magic = [0u8; MAGIC_MAX_LEN];
    magic[..MAGIC.len()].copy_from_slice(MAGIC);
    let mut nonce = [0u8; FILE_NONCEBYTES];
    nonce.copy_from_slice(&file_nonce); // cipher.get_nonce()
    let mut tag = [0u8; TAGBYTES];
    tag.copy_from_slice(file_tag.get_slice());
    let header = &EncHeader {
        magic,
        format_version: FORMAT_VERSION,
        envelope_size: key_buf.len() as u32,
        cipher_kind: opt.cipher.clone(),
        nonce,
        tag,
    };
    let hdr_buf = bincode::serialize(&header)?;
    assert_eq!(hdr_buf.len(), HEADER_LEN);

    // write header, key envelope, and encrypted file
    let mut file = File::create(&opt.output).await?;
    file.write_all(&hdr_buf).await?;
    file.write_all(&key_buf).await?;
    file.write_all(&buf).await?;
    file.sync_all().await?; // flush file and metadata to disk before returning
    Ok(())
}

/// load header and wrapped key
/// after loading, file reader is positioned at the start of the encrypted file blob
async fn load_header(file: &mut File) -> Result<(EncHeader, WrappedKey), Error> {
    let mut hdr_buf = uninitialized_bytes(HEADER_LEN);
    let _ = file.read_exact(&mut hdr_buf).await?;
    let header: EncHeader = bincode::deserialize(&hdr_buf)?;
    if header.format_version != FORMAT_VERSION || !MAGIC.eq(&header.magic[..MAGIC.len()]) {
        return Err(Error::InvalidFile(String::from("")));
    }
    let mut key_buf = uninitialized_bytes(header.envelope_size as usize);
    let _ = file.read_exact(&mut key_buf).await?;
    let envelope: WrappedKey = bincode::deserialize(&key_buf)?;
    Ok((header, envelope))
}

/// Decrypt file
pub(crate) async fn decrypt_file(opt: &DecryptOptions) -> Result<(), Error> {
    let mut file = File::open(&opt.file).await?;
    let (header, wkey) = load_header(&mut file).await?;
    let file_size = file.metadata().await?.len();
    let blob_size = file_size - (HEADER_LEN as u64) - (header.envelope_size as u64);

    let keeper = SecretKeeper::for_uri(&opt.keeper_uri).await?;
    let cipher = keeper
        .init_cipher(header.cipher_kind, &header.nonce, Some(&wkey))
        .await?;
    let buf = cipher
        .open_read(&mut file, blob_size, None, &header.tag, None)
        .await?;
    let mut output = File::create(&opt.output).await?;
    output.write_all(&buf).await?;
    Ok(())
}

async fn view_key(opt: &ViewKeyOptions) -> Result<(), Error> {
    let mut file = File::open(&opt.file).await?;
    let (_, envelope) = load_header(&mut file).await?;

    println!("{:#?}", envelope);
    Ok(())
}

#[cfg(test)]
mod test;
