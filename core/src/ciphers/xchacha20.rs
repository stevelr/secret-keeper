//! # xchacha20 cipher
//!
//! XChaCha20-Poly1305 encryption cipher
//!

#[cfg(feature = "fileio")]
use crate::ciphers::read_file;
use crate::{
    cipher_impl, cipher_keybox,
    ciphers::{Cipher, Import},
    clone_slice,
    error::{Error, Result},
    keepers::SecretKeeper,
    rand, AuthTag, WrappedKey,
};
use async_trait::async_trait;
use bytes::Bytes;
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, AeadInPlace, NewAead};
use chacha20poly1305::XChaCha20Poly1305 as pxchacha;
use hex;
use std::fmt;
#[cfg(feature = "fileio")]
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use typenum::{U24, U32};
use zeroize::Zeroize;

/// Number of bytes in key
pub const KEYBYTES: usize = 32;
/// Number of bytes in nonce
pub const NONCEBYTES: usize = 24;
/// Number of bytes in auth integrity tag
pub const TAGBYTES: usize = 16;

type PKey = GenericArray<u8, U32>;
type PNonce = GenericArray<u8, U24>;

clone_slice!(tag_from, TAGBYTES);

cipher_keybox! {
    'kbx,
    PKey,
    KEYBYTES,   // keylen
    (|s: &[u8]| *GenericArray::from_slice(s)),
    (|k: &'kbx PKey | k.as_slice()),
    PNonce,
    NONCEBYTES,
    (|s: &[u8]| *GenericArray::from_slice(s)),
    (|n: &'kbx PNonce| n.as_slice()),
    PTag,
    TAGBYTES,
    (|s: &[u8]| *GenericArray::from_slice(s)),
}

/// XChaCha20-Poly1305 encryption cipher
/// Encryption algorithm is a pure rust implementation by
/// [RustCrypto AEAD](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)
pub struct XChaCha20 {
    kbox: KeyBox,
    aead: pxchacha,
}

/// Implementation of Debug that doesn't print key to prevent accidental leaks via logging
impl fmt::Debug for XChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha20")
            .field("kbox", &self.kbox)
            .finish()
    }
}

impl XChaCha20 {
    /// Initialize cipher with provided key and nonce
    /// key length must be exactly KEYBYTES. nonce length must be >= NONCEBYTES
    pub fn init_from(key: &[u8], nonce: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            kbox: KeyBox::init(
                KeyBox::key_from_slice(&key)?,
                KeyBox::nonce_from_slice(&nonce[..NONCEBYTES])?,
            ),
            aead: pxchacha::new(GenericArray::from_slice(key)),
        })
    }

    /// Initialize cipher, generating new key and nonce
    /// Key is generated with crate::rand (platform CSRNG)
    pub fn init() -> Result<Self, Error> {
        let nonce = KeyBox::new_nonce()?;
        Self::with_nonce(&nonce)
    }

    /// Initialize cipher with nonce, generating new key
    /// Key is generated with crate::rand (platform CSRNG)
    /// Nonce length must be >= NONCEBYTES
    pub fn with_nonce(nonce: &[u8]) -> Result<Self, Error> {
        let key = KeyBox::new_key()?;
        Self::init_from(&key, nonce)
    }
}

#[async_trait]
impl Cipher for XChaCha20 {
    // implementation of functions: nonce_len, key_len, get_nonce
    cipher_impl!();

    /// Returns whether or not this encryption supports aad
    fn supports_aad(&self) -> bool {
        false
    }

    /// Encrypts the slice, with optional authenticated data
    /// Return value is a simple vector that contains the ciphertext
    /// plus a MAC-based authentication tag.
    async fn seal(&self, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<Bytes, Error> {
        Ok(Bytes::from(
            self.aead.encrypt(&self.kbox.get_nonce(), plaintext)?,
        ))
    }

    /// Decrypts the in-memory block, with optional authenticated data
    async fn open(&self, ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Bytes, Error> {
        Ok(Bytes::from(
            self.aead.decrypt(self.kbox.get_nonce(), ciphertext)?,
        ))
    }

    async fn seal_detached(&self, src: &mut [u8], _aad: Option<&[u8]>) -> Result<AuthTag, Error> {
        let tag = self
            .aead
            .encrypt_in_place_detached(&self.kbox.get_nonce(), &[], src)?;
        Ok(AuthTag::from_slice(tag_from(tag.as_slice())))
    }

    /// Encrypts the file, with optional associated data,
    /// Returns encrypted data, tag, and file size
    /// (requires "fileio" feature, included in default)
    #[cfg(feature = "fileio")]
    async fn seal_file(
        &self,
        file_path: &str,
        _aad: Option<&[u8]>,
    ) -> Result<(Bytes, AuthTag, u64), Error> {
        let src_len = fs::metadata(file_path).await?.len();
        let mut fvec = tokio::fs::read(file_path).await?;
        // encrypt in place, freeze, and return the bytes buffer
        let tag = self
            .aead
            .encrypt_in_place_detached(&self.kbox.get_nonce(), &[], &mut fvec)?;
        Ok((
            Bytes::from(fvec),
            AuthTag::from_slice(tag_from(tag.as_slice())),
            src_len,
        ))
    }

    /// Encrypt the data and append to the file. Returns the auth tag and length of data appended
    /// (requires "fileio" feature, included in default)
    #[cfg(feature = "fileio")]
    async fn seal_write(
        &self,
        data: &mut [u8],
        file: &mut File,
        _aad: Option<&[u8]>,
    ) -> Result<(AuthTag, u64), Error> {
        let tag = self
            .aead
            .encrypt_in_place_detached(&self.kbox.get_nonce(), &[], data)?;
        let _ = file.write_all(data).await?;
        Ok((
            AuthTag::from_slice(tag_from(tag.as_slice())),
            data.len() as u64,
        ))
    }

    /// Read len bytes from the file and decrypt
    /// Returns data as Bytes
    /// In non-compressing cipher, data.len() == len, so size_hint is ignored.
    #[cfg(feature = "fileio")]
    async fn open_read(
        &self,
        file: &mut File,
        len: u64,
        _size_hint: Option<u64>,
        tag: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Bytes, Error> {
        let mut buf = read_file(file, len as usize).await?;
        self.aead.decrypt_in_place_detached(
            self.kbox.get_nonce(),
            &[],
            buf.as_mut(),
            GenericArray::from_slice(tag),
        )?;
        Ok(buf.freeze())
    }

    /// Decrypts the data in-place
    /// buf: mutable buffer containing ciphertext (in), to be overwritten with plaintext
    /// tag: auth tag data
    /// aad: optional additional authenticated data
    async fn open_detached(
        &self,
        buf: &mut [u8],
        tag: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.aead.decrypt_in_place_detached(
            self.kbox.get_nonce(),
            &[],
            buf,
            GenericArray::from_slice(tag),
        )?;
        Ok(())
    }

    /// Export key by encrypting and wrapping it
    async fn export(
        &self,
        uri: &str,
        nonce: &[u8],
        keeper: &Box<dyn SecretKeeper>,
    ) -> Result<WrappedKey, Error> {
        self.kbox.export(uri, nonce, keeper).await
    }
}

#[async_trait]
impl Import for XChaCha20 {
    /// Import key by unwrapping and decrypting it
    async fn import(
        nonce: &[u8],
        keeper: &Box<dyn SecretKeeper>,
        wrapped: &WrappedKey,
    ) -> Result<Self, Error> {
        let kbox = KeyBox::import(&nonce, keeper, wrapped).await?;
        let aead = pxchacha::new(&kbox.key);
        Ok(Self { kbox, aead })
    }
}
