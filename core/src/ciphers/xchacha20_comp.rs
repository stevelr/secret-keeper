//! # XChaCha20-Poly1305 cipher with LZ4 compression
//!
//! This implementation attempts to minimize copying by re-using buffers when possible.
//! The compression and encryption implementations are not stream-oriented - the buffers
//! must fit in (virtual) memory.
//!
//! Encryption algorithm is a pure rust implementation by
//! [RustCrypto AEAD](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)
//!
//! LZ4 compression algorithm is a pure rust implementation by
//! [`lz_fear`](https://crates.io/crates/lz-fear).

use crate::{
    cipher_impl, cipher_keybox,
    ciphers::{Cipher, CompressingCipher, Import},
    clone_slice,
    error::{Error, Result},
    keepers::SecretKeeper,
    rand,
    util::{self, Compressor, Uncompressor},
    AuthTag, WrappedKey,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::{generic_array::GenericArray, Aead, AeadInPlace, NewAead};
use chacha20poly1305::XChaCha20Poly1305 as pxchacha;
use std::fmt;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use typenum::{U24, U32};
use zeroize::Zeroize;

/// Number of bytes in key
pub const KEYBYTES: usize = 32;
/// Number of bytes in nonce
pub const NONCEBYTES: usize = 24;
/// Number of bytes in auth integrity tag
pub const TAGBYTES: usize = 16;

// smallest buffer we will create to uncompress into
const MIN_UNCOMPRESS_BUFSIZE: usize = 8196;

type PKey = GenericArray<u8, U32>;
type PNonce = GenericArray<u8, U24>;

#[macro_use]
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

/// XChaCha20-Poly1305 cipher with LZ4 compression
pub struct XChaCha20Compress {
    kbox: KeyBox,
    aead: pxchacha,
}

/// Implementation of Debug that doesn't print key to prevent accidental leaks via logging
impl fmt::Debug for XChaCha20Compress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha20")
            .field("kbox", &self.kbox)
            .finish()
    }
}

impl XChaCha20Compress {
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
impl CompressingCipher for XChaCha20Compress {
    /// Compress and encrypt the slice, with optional associated data.
    async fn seal_compressed(
        &self,
        src: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<(Bytes, AuthTag), Error> {
        let mut compbuf = BytesMut::with_capacity(MIN_UNCOMPRESS_BUFSIZE);
        let _ = Compressor::new().from_buf(&src, &mut compbuf)?;

        let tag =
            self.aead
                .encrypt_in_place_detached(&self.kbox.get_nonce(), &[], compbuf.as_mut())?;
        Ok((
            compbuf.freeze(),
            AuthTag::from_slice(tag_from(tag.as_slice())),
        ))
    }

    /// Decrypt slice into the provided buffer.
    /// src: compressed ciphertext
    /// tag: auth tag
    /// size_hint: optional size used to allocate buffer for result
    async fn open_compressed(
        &self,
        src: &mut [u8],
        tag: &[u8],
        size_hint: Option<u64>,
        _aad: Option<&[u8]>,
    ) -> Result<Bytes, Error> {
        self.aead.decrypt_in_place_detached(
            self.kbox.get_nonce(),
            &[],
            src,
            GenericArray::from_slice(tag),
        )?;

        let mut dest = match size_hint {
            Some(len) => BytesMut::with_capacity(len as usize),
            // If they didn't give a size hint before, start with a chunk size
            // to reduce heap churn. std::io::copy uses 8k which seems reasonable.
            None => BytesMut::with_capacity(std::cmp::max(src.len(), MIN_UNCOMPRESS_BUFSIZE)),
        };
        let _ = Uncompressor::new().from_slice(src, &mut dest).await?;
        Ok(dest.freeze())
    }
}

#[async_trait]
impl Cipher for XChaCha20Compress {
    // implementation of functions: nonce_len, key_len, get_nonce
    cipher_impl! {}

    /// Returns whether or not this encryption supports aad
    fn supports_aad(&self) -> bool {
        false
    }

    /// Encrypts the slice, with optional authenticated data
    /// Return value is a simple vector that contains the ciphertext
    /// plus a MAC-based authentication tag.
    async fn seal(&self, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<Bytes, Error> {
        let mut compbuf = BytesMut::with_capacity(MIN_UNCOMPRESS_BUFSIZE);
        let _ = Compressor::new().from_buf(&plaintext, &mut compbuf);
        compbuf.reserve(TAGBYTES);

        // TODO: add pull request for aead::Buffer to impl From<BytesMut>
        let tag =
            self.aead
                .encrypt_in_place_detached(self.kbox.get_nonce(), &[], compbuf.as_mut())?;
        compbuf.extend_from_slice(tag.as_slice());
        Ok(compbuf.freeze())
    }

    /// Decrypts and uncompresses the slice. The ciphertext buffer was
    /// created with seal(), and contains an appended auth tag.
    /// This method may be less efficient than open_detached,
    /// because it needs to make two heap allocs: one for decryption, and one for decompression.
    /// If you can use open_detached, the decryption is done in place so the first alloc
    /// is avoided. Return value is the decrypted plaintext.
    async fn open(&self, ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Bytes, Error> {
        let plaincomp = self.aead.decrypt(self.kbox.get_nonce(), ciphertext)?;
        let mut decomp = BytesMut::with_capacity(MIN_UNCOMPRESS_BUFSIZE);
        let _ = Uncompressor::new()
            .from_slice(&plaincomp, &mut decomp)
            .await?;
        Ok(decomp.freeze())
    }

    /// Compress and encrypt the file, with optional associated data.
    async fn seal_file(
        &self,
        file_path: &str,
        _aad: Option<&[u8]>,
    ) -> Result<(Bytes, AuthTag, u64), Error> {
        let mut compbuf = BytesMut::with_capacity(MIN_UNCOMPRESS_BUFSIZE);
        let src_len = tokio::fs::metadata(file_path).await?.len();
        let _ = Compressor::new().from_file(file_path, &mut compbuf).await?;
        let tag =
            self.aead
                .encrypt_in_place_detached(self.kbox.get_nonce(), &[], compbuf.as_mut())?;
        Ok((
            compbuf.freeze(),
            AuthTag::from_slice(tag_from(tag.as_slice())),
            src_len,
        ))
    }

    /// Encrypt the data and append to the file. Returns the auth tag and length of data appended
    async fn seal_write(
        &self,
        data: &mut [u8],
        file: &mut File,
        _aad: Option<&[u8]>,
    ) -> Result<(AuthTag, u64), Error> {
        let mut compbuf = BytesMut::with_capacity(MIN_UNCOMPRESS_BUFSIZE);
        let data_rd: &[u8] = data; // type cast to non-mutable so from_buf works
        let _ = Compressor::new().from_buf(&data_rd, &mut compbuf)?;
        let tag =
            self.aead
                .encrypt_in_place_detached(self.kbox.get_nonce(), &[], compbuf.as_mut())?;
        let _ = file.write_all(compbuf.as_ref()).await?;
        Ok((
            AuthTag::from_slice(tag_from(tag.as_slice())),
            compbuf.len() as u64,
        ))
    }

    /// Read len bytes from the file and decrypt
    /// Returns data as Bytes. In compressing cipher, size_hint should be used
    /// if size of decompressed data is known.
    async fn open_read(
        &self,
        file: &mut File,
        len: u64,
        size_hint: Option<u64>,
        tag: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Bytes, Error> {
        let mut buf = util::uninitialized_bytes(len as usize);
        let _ = file.read_exact(buf.as_mut()).await?;
        let _ = self.aead.decrypt_in_place_detached(
            self.kbox.get_nonce(),
            &[],
            buf.as_mut(), // TODO: need to reset reader?
            GenericArray::from_slice(tag),
        )?;
        let mut decomp = BytesMut::with_capacity(match size_hint {
            Some(sz) => std::cmp::min(MIN_UNCOMPRESS_BUFSIZE, sz as usize),
            None => MIN_UNCOMPRESS_BUFSIZE,
        });
        let _ = Uncompressor::new().from_slice(&buf, &mut decomp).await?;
        Ok(decomp.freeze())
    }

    /// Encrypt the slice, with optional associated data.
    async fn seal_detached(
        &self,
        mut src: &mut [u8],
        _aad: Option<&[u8]>,
    ) -> Result<AuthTag, Error> {
        let tag = self
            .aead
            .encrypt_in_place_detached(&self.kbox.get_nonce(), &[], &mut src)?;
        Ok(AuthTag::from_slice(tag_from(tag.as_slice())))
    }

    /// Decrypts the data in-place
    /// Note: this is not applicable for compressed encryptors because the
    /// decrypted data may exceed the provided buffer length. Use open_compressed instead.
    async fn open_detached(
        &self,
        _buf: &mut [u8],
        _tag: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        return Err(Error::OtherError(String::from(
            "Not implemented for compressing encryptors. Please use open_compressed",
        )));
    }

    /// Export key by encrypting and wrapping it
    async fn export(
        &self,
        uri: &str,
        nonce: &[u8],
        keeper: &Box<dyn SecretKeeper>,
    ) -> Result<WrappedKey, Error> {
        self.kbox.export(uri, &nonce, keeper).await
    }
}

#[async_trait]
impl Import for XChaCha20Compress {
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
