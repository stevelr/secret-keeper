/// Cipher implementation of AES-GCM (Galois/Counter Mode) with 256-bit keys
pub mod aesgcm256 {

    // `RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`
    use crate::{
        cipher_impl, cipher_keybox,
        ciphers::{Cipher, Import},
        clone_slice,
        error::{Error, Result},
        keepers::SecretKeeper,
        rand, util, AuthTag, WrappedKey,
    };
    //use aes_gcm::aead::heapless::Vec;
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, AeadInPlace, NewAead},
        Aes256Gcm,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use hex;
    use std::fmt;
    use tokio::fs::{self, File};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use typenum::{U12, U32};
    use zeroize::Zeroize;

    /// Number of bytes in encryption key for AES_GCM (256 bits = 32 bytes)
    pub const KEYBYTES: usize = 32;
    /// Number of bytes in nonce (96 bites = 12 bytes)
    pub const NONCEBYTES: usize = 12;
    /// Number of bytes in auth integrity tag
    pub const TAGBYTES: usize = 16;

    type PKey = GenericArray<u8, U32>;
    type PNonce = GenericArray<u8, U12>;

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

    /// Cipher implementation of AES-GCM (Galois/Counter Mode) with 256-bit keys
    /// with optional architecture-specific hardware acceleration
    /// encryption implemented by [RustCrypto](htttps://github.com/RustCrypto/AEADs)
    ///
    /// When targeting modern x86/x86_64 CPUs, use the following `RUSTFLAGS` to
    /// take advantage of high performance AES-NI and CLMUL CPU intrinsics:
    pub struct AesGcm256 {
        kbox: KeyBox,
        aesgcm: Aes256Gcm,
    }

    /// Implementation of Debug that doesn't print key to prevent accidental leaks via logging
    impl fmt::Debug for AesGcm256 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AesGcm256")
                .field("kbox", &self.kbox)
                .finish()
        }
    }

    impl AesGcm256 {
        /// Initialize cipher with provided key and nonce
        /// key length must be exactly KEYBYTES. nonce length must be >= NONCEBYTES
        pub fn init_from(key: &[u8], nonce: &[u8]) -> Result<Self, Error> {
            Ok(Self {
                kbox: KeyBox::init(
                    KeyBox::key_from_slice(&key)?,
                    KeyBox::nonce_from_slice(&nonce[..NONCEBYTES])?,
                ),
                aesgcm: Aes256Gcm::new(GenericArray::from_slice(key)),
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
    impl Cipher for AesGcm256 {
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
                self.aesgcm.encrypt(self.kbox.get_nonce(), plaintext)?,
            ))
        }

        /// Decrypts the in-memory block, with optional authenticated data
        async fn open(&self, ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Bytes, Error> {
            Ok(Bytes::from(
                self.aesgcm.decrypt(self.kbox.get_nonce(), ciphertext)?,
            ))
        }

        async fn seal_detached(
            &self,
            src: &mut [u8],
            aad: Option<&[u8]>,
        ) -> Result<AuthTag, Error> {
            let aad = match aad {
                Some(a) => a,
                None => &[],
            };
            // encrypt in place, freeze, and return the bytes buffer
            let tag = self
                .aesgcm
                .encrypt_in_place_detached(self.kbox.get_nonce(), aad, src)?;
            Ok(AuthTag::from_slice(tag_from(tag.as_slice())))
        }

        /// Encrypts the file, with optional associated data,
        /// Returns encrypted data, tag, and file size
        async fn seal_file(
            &self,
            file_path: &str,
            aad: Option<&[u8]>,
        ) -> Result<(Bytes, AuthTag, u64), Error> {
            let src_len = fs::metadata(file_path).await?.len();
            let mut fvec = tokio::fs::read(file_path).await?;
            let aad = match aad {
                Some(a) => a,
                None => &[],
            };
            // encrypt in place, freeze, and return the bytes buffer
            let tag =
                self.aesgcm
                    .encrypt_in_place_detached(self.kbox.get_nonce(), aad, &mut fvec)?;
            Ok((
                Bytes::from(fvec),
                AuthTag::from_slice(tag_from(tag.as_slice())),
                src_len,
            ))
        }

        /// Encrypt the data and append to the file. Returns the auth tag and length of data appended
        async fn seal_write(
            &self,
            mut data: &mut [u8],
            file: &mut File,
            aad: Option<&[u8]>,
        ) -> Result<(AuthTag, u64), Error> {
            let aad = match aad {
                Some(a) => a,
                None => &[],
            };
            let tag =
                self.aesgcm
                    .encrypt_in_place_detached(self.kbox.get_nonce(), aad, &mut data)?;
            let _ = file.write_all(data).await?;
            Ok((
                AuthTag::from_slice(tag_from(tag.as_slice())),
                data.len() as u64,
            ))
        }

        /// Read len bytes from the file and decrypt
        /// Returns data as Bytes
        /// In non-compressing cipher, data.len() == len, so size_hint is ignored.
        async fn open_read(
            &self,
            file: &mut File,
            len: u64,
            _size_hint: Option<u64>,
            tag: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Bytes, Error> {
            let aad = match aad {
                Some(a) => a,
                None => &[],
            };
            let mut buf = util::uninitialized_bytes(len as usize);
            let _ = file.read_exact(buf.as_mut()).await?;
            self.aesgcm.decrypt_in_place_detached(
                self.kbox.get_nonce(),
                aad,
                &mut buf,
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
            mut buf: &mut [u8],
            tag: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<(), Error> {
            let aad = match aad {
                Some(a) => a,
                None => &[],
            };
            self.aesgcm.decrypt_in_place_detached(
                self.kbox.get_nonce(),
                aad,
                &mut buf,
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
            self.kbox.export(uri, &nonce, keeper).await
        }
    }

    #[async_trait]
    impl Import for AesGcm256 {
        /// Import key by unwrapping and decrypting it
        async fn import(
            nonce: &[u8],
            keeper: &Box<dyn SecretKeeper>,
            wrapped: &WrappedKey,
        ) -> Result<Self, Error> {
            let kbox = KeyBox::import(&nonce[..NONCEBYTES], keeper, wrapped).await?;
            let aesgcm = Aes256Gcm::new(&kbox.key);
            Ok(Self { kbox, aesgcm })
        }
    }
}
