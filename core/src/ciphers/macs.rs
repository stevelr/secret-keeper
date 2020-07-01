//! Macros to assist with SecretKeeper implementations
//!
#[doc(hidden)]
pub mod macros {

    /// Creates a function that clones a slice of the given length
    /// `ident` is the name of the function, `len` is the size of the slice.
    /// Example:
    /// `clone_slice(make_key, 5)` generates  `fn make_key(s: &[u8]) -> [u8;5]`
    ///
    #[doc(hidden)]
    #[macro_export]
    macro_rules! clone_slice {
        ($fname: ident, $len: expr) => {
            fn $fname(s: &[u8]) -> [u8; $len] {
                let mut v: [u8; $len] = [0u8; $len];
                for i in 0..$len {
                    v[i] = s[i];
                }
                v
            }
        };
    }

    #[doc(hidden)]
    #[macro_export]
    macro_rules! WithAuthTag {
        ( $tagtype: ident,
            $taglen: expr) => {
            #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
            pub struct $tagtype(pub [u8; $taglen]);

            /// mac integrity tag generated during encryption, verified during decryption
            impl $tagtype {
                pub fn new() -> Self {
                    Self { 0: [0u8; $taglen] }
                }
                pub fn from_slice(t: [u8; $taglen]) -> Self {
                    assert!(t.len() == $taglen);
                    Self { 0: t }
                }
            }
        };
    }

    /// This macro, used by Cipher implementations,
    /// provides a `struct KeyBox` containing sized key and nonce arrays.
    /// See [cipher implementations](https://github.com/stevelr/secret-keeper/tree/master/core/src/ciphers)
    /// for implementation examples
    #[macro_export]
    macro_rules! cipher_keybox {
        ($lifetm: lifetime,
         $keytype:ty,
         $keylen:expr,
         $keyfromslice: expr,
         $keytoslice: expr,
         $noncetype:ty,
         $noncelen: expr,
         $noncefromslice: expr,
         $noncetoslice: expr,
         $tagtype:ty,
         $taglen:expr,
         $tagfromslice: expr,
         ) => {
            #[derive(Zeroize)]
            #[zeroize(drop)]
            struct KeyBox {
                // key: [u8; $keylen],
                key: $keytype,
                //nonce: [u8; $noncelen],
                nonce: $noncetype,
            }

            impl<'kbx> KeyBox {
                fn init(key: $keytype, nonce: $noncetype) -> Self {
                    Self { key, nonce }
                }

                /// Generate new random key using crate's RNG
                /// Should only return error if platform rng is broken
                pub fn new_key() -> Result<[u8; $keylen], Error> {
                    let mut key = [0u8; $keylen];
                    rand::fill_buf(&mut key)?;
                    Ok(key)
                }

                /// Generate new random nonce using crate's RNG
                /// Should only return error if platform rng is broken
                pub fn new_nonce() -> Result<[u8; $noncelen], Error> {
                    let mut nonce = [0u8; $noncelen];
                    rand::fill_buf(&mut nonce)?;
                    Ok(nonce)
                }

                pub fn key_len() -> usize {
                    $keylen
                }

                pub fn nonce_len() -> usize {
                    $noncelen
                }

                pub fn tag_len() -> usize {
                    $taglen
                }

                /// returns nonce
                pub fn get_nonce(&self) -> &$noncetype {
                    &self.nonce
                }

                /// returns key
                #[cfg(feature = "crypto_nacl")]
                pub fn get_key(&self) -> &$keytype {
                    &self.key
                }

                /// returns nonce as slice
                pub fn nonce_slice(&'kbx self) -> &'kbx [u8] {
                    $noncetoslice(&self.nonce)
                }

                /// Export key by encrypting and wrapping it
                pub async fn export(
                    &'kbx self,
                    uri: &str,
                    nonce: &[u8],
                    keeper: &Box<dyn SecretKeeper>,
                ) -> Result<WrappedKey, Error> {
                    keeper.wrap(uri, nonce, $keytoslice(&self.key)).await
                }

                /// Import key by unwrapping and decrypting it
                /// Fails if keeper or key is wrong
                pub async fn import(
                    nonce: &[u8],
                    keeper: &Box<dyn SecretKeeper>,
                    wrapped: &WrappedKey,
                ) -> Result<Self, Error> {
                    let new_key: Bytes = keeper.unwrap(nonce, wrapped).await.map_err(|e| {
                        Error::OtherError(format!("Decrypt key: {}", e).to_string())
                    })?;
                    assert_eq!(new_key.len(), $keylen);
                    Ok(Self {
                        key: Self::key_from_slice(&new_key)?,
                        nonce: Self::nonce_from_slice(&nonce)?,
                    })
                }

                /// convert slice to Key, with error handling
                pub fn key_from_slice(key: &[u8]) -> Result<$keytype, Error> {
                    if key.len() != $keylen {
                        Err(Error::InvalidParameter(
                            format!("Invalid key length {}", key.len()).to_string(),
                        ))
                    } else {
                        Ok($keyfromslice(key))
                    }
                }

                /// convert slice to Nonce, with error handling
                pub fn nonce_from_slice(nonce: &[u8]) -> Result<$noncetype, Error> {
                    if nonce.len() != $noncelen {
                        Err(Error::InvalidParameter(format!(
                            "Invalid nonce length {} expected {}",
                            nonce.len(),
                            $noncelen
                        )))
                    } else {
                        Ok($noncefromslice(nonce))
                    }
                }

                /// convert slice to Tag, with error handling
                #[cfg(feature = "crypto_nacl")]
                pub fn tag_from_slice(tag: &[u8]) -> Result<$tagtype, Error> {
                    if tag.len() != $taglen {
                        Err(Error::InvalidParameter("Invalid tag length".to_string()))
                    } else {
                        Ok($tagfromslice(tag))
                    }
                }
            }

            /// Implement Display for KeyBox that prevents accidental logging of secret key
            impl fmt::Display for KeyBox {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        f,
                        "(Key:{}B:SECRET, Nonce:{}B:{})",
                        $keylen,
                        $noncelen,
                        hex::encode(self.nonce_slice()),
                    )
                }
            }

            impl fmt::Debug for KeyBox {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(
                        f,
                        "(Key:{}B:SECRET, Nonce:{}B:{})",
                        $keylen,
                        $noncelen,
                        hex::encode(self.nonce_slice()),
                    )
                }
            }
        };
    }

    /// implementation methods for Cipher
    #[doc(hidden)]
    #[macro_export]
    macro_rules! cipher_impl {
        () => {
            /// number of bytes in nonce for this cipher
            fn nonce_len(&self) -> usize {
                KeyBox::nonce_len()
            }

            /// number of bytes in key for this cipher
            fn key_len(&self) -> usize {
                KeyBox::key_len()
            }

            fn tag_len(&self) -> usize {
                KeyBox::tag_len()
            }

            /// return nonce as slice
            fn get_nonce(&self) -> &[u8] {
                self.kbox.nonce_slice()
            }
        };
    }

    #[cfg(feature = "debug")]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! traitdebug {
        ($trait:ident) => {
            $trait: fmt::Debug
        };
    }

    #[cfg(not(feature = "debug"))]
    #[doc(hidden)]
    #[macro_export]
    macro_rules! traitdebug {
        ($trait:ident) => {
            $trait
        };
    }
}
