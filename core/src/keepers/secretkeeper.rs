use crate::{
    ciphers::{
        aesgcm256::AesGcm256, xchacha20::XChaCha20, xchacha20_comp::XChaCha20Compress, Cipher,
        CipherKind,
    },
    error::{Error, Result},
    keepers::env::EnvKeeper,
    WrappedKey,
};
use async_trait::async_trait;
use bytes::Bytes;
use lazy_static::lazy_static;
use std::fmt;
use std::sync::Arc;

/// SecretKeeper encrypts and decrypts data-encryption keys
#[async_trait]
pub trait SecretKeeper: fmt::Debug + Sync + Send {
    /// Initialize a new encryption cipher.
    ///
    /// If `wrappedKey` has a value, it is decrypted by the SecretKeeper,
    /// and the resulting key is used to initialize the cipher.
    /// If `wrappedKey` is None, the cipher is initalized with
    /// a new key generated by the platform's CSRNG.
    ///
    /// `nonce`: A nonce that will initialize the content cipher and also may be used by some keepers
    /// (including 'env' and 'prompt') to initialize the keeper's cipher for key encryption.
    /// TL;DR: nonce should be 24 random bytes; you can use secret_keeper::rand to initialize it.
    ///
    /// In more detail, for env and prompt keepers, the nonce parameter must be
    /// at least 24 bytes, even if the cipher is AES_GCM_256, which uses a 12 byte nonce,
    /// because the 24-byte nonce is used for encrypting and decrypting the key
    /// using xchacha20-poly1305 in the envelope.
    /// If AesGcm256 is the chosen CipherKind, the first 12 bytes of the nonce parameter
    /// will be used to initialize the AesGcm256 cipher.
    /// For other keepers (hashivault, cloudkms, etc.) that encrypt keys with an external service,
    /// the nonce length can be whatever NONCEBYTES is required by the desired cipher.
    /// For the most flexible code, 24 bytes always is recommended.
    async fn init_cipher(
        &self,
        ckind: CipherKind,
        nonce: &[u8],
        wrapped: Option<&WrappedKey>,
    ) -> Result<Box<dyn Cipher>, Error> {
        match wrapped {
            Some(wrapped) => {
                let key = self.unwrap(&nonce, wrapped).await?;
                match ckind {
                    CipherKind::AesGcm256 => Ok(Box::new(AesGcm256::init_from(&key, &nonce)?)),
                    CipherKind::LZ4XChaCha20Poly1305 => {
                        Ok(Box::new(XChaCha20Compress::init_from(&key, &nonce)?))
                    }
                    CipherKind::XChaCha20Poly1305 => {
                        Ok(Box::new(XChaCha20::init_from(&key, &nonce)?))
                    }
                }
            }
            None => match ckind {
                CipherKind::AesGcm256 => Ok(Box::new(AesGcm256::with_nonce(&nonce)?)),
                CipherKind::LZ4XChaCha20Poly1305 => {
                    Ok(Box::new(XChaCha20Compress::with_nonce(&nonce)?))
                }
                CipherKind::XChaCha20Poly1305 => Ok(Box::new(XChaCha20::with_nonce(&nonce)?)),
            },
        }
    }

    /// Encrypts key and packages in a format that can be transmitted or stored on disk.
    /// Applications should use Cipher::export to encrypt and wrap data encryption keys,
    /// instead of calling this function. This function is called by ciphers
    /// from Cipher::export.
    ///
    /// The `nonce` parameter is used by some SecretKeepers during the key encryption process.
    /// After encryption, the Key is stringified with bech32.
    async fn wrap(&self, uri: &str, nonce: &[u8], key: &[u8]) -> Result<WrappedKey, Error>;

    /// Unwraps and decrypts data-encryption key.
    /// Applications should use init_cipher to unwrap a key and create a cipher, rather
    /// than calling this function directly.
    async fn unwrap(&self, nonce: &[u8], wk: &WrappedKey) -> Result<Bytes, Error>;

    /// Returns uri scheme for this keeper
    fn get_scheme(&self) -> &str;

    /// attempts to cast keeper to Create. Returns Error if create() is not implemented.
    fn as_create(&self) -> Result<&dyn Create, Error> {
        // The default implementation here returns error.
        // SecretKeepers that can create keys should override this.
        Err(Error::CastError("Create".to_string()))
    }
}

/// Trait describing a SecretKeeper that can create keys
#[async_trait]
pub trait Create: SecretKeeper {
    /// Creates a new encryption key.
    /// `key_name` is any valid key name
    /// `params` are url-encoded parameters that can be created with
    /// [`serde_urlencoded`](https://docs.rs/serde_urlencoded/0.6.1/serde_urlencoded/fn.to_string.html)
    ///
    /// It is expected that this call should work with an empty params string, using
    /// defaults filled in by the keeper itself and/or environment variables.
    ///
    /// Refer to specific SecretKeeper implementations for documentation about applicable `params`.
    ///
    async fn create_key(&self, key_name: &str, params: &str) -> Result<(), Error>;
}

// Maintain a list of registered SecretKeepers that can be discovered with
// SecretKeeper::for_uri().
// A set of built-in default SecretKeepers is registered automatically. Other SecretKeepers
// implemented as separate crates can be registered by applications that need them.
// Any SecretKeeper that is not pure rust, (or that would prevent secret-keeper core from
// compiling to wasm) should be implemented as a separate optional crate. Additionally,
// SecretKeepers that depend on external services (such as a Google Cloud account) should
// be packaged separately from the core library.
mod keeper_list {

    use super::*;
    use tokio::sync::RwLock;

    #[derive(PartialEq)]
    /// "boolean" flag that indicates whether the default set of SecretKeepers has been registered
    enum DefaultsRegistered {
        Registered,
        Not,
    }

    lazy_static! {
        /// List of registered SecretKeepers is implemented as a static singleton
        static ref KEEPERS: RwLock<Vec<Arc<Box<dyn SecretKeeper>>>> = RwLock::new(Vec::new());

        /// Rather than forcing every App using this library to call register_defaults()
        /// during main(), we do the registration automatically, and lazily: the first
        /// time someone calls find(). The tradeoff is that we need to check this static value
        /// during every invocation of find().
        static ref DEFAULTS_REGISTERED: RwLock<DefaultsRegistered> =
            RwLock::new(DefaultsRegistered::Not);
    }

    /// add a keeper
    /// Does not return error if keeper is already registered
    pub async fn add(keeper: Box<dyn SecretKeeper>) -> Result<(), Error> {
        let mut klist = KEEPERS.write().await;

        let scheme: &str = keeper.get_scheme();
        if klist.iter().find(|&k| k.get_scheme() == scheme).is_none() {
            klist.push(Arc::new(keeper));
        }
        Ok(())
    }

    #[cfg(test)]
    /// Unregisters a secret keeper.
    /// Does not return error if keeper has already been removed.
    /// Currently, this function is only used by unit tests.
    pub async fn remove(scheme: &str) {
        let mut klist = KEEPERS.write().await;
        let index = {
            match klist
                .iter()
                .enumerate()
                .find(|k| k.1.get_scheme() == scheme)
            {
                Some(k) => k.0,
                None => return,
            }
        };
        klist.remove(index);
    }

    /// Returns true if the crate's default keepers have been registered.
    async fn registered_defaults() -> bool {
        let reg = DEFAULTS_REGISTERED.read().await;
        *reg == DefaultsRegistered::Registered
    }

    /// returns keeper if it is in list, otherwise None
    pub async fn find(scheme: &str) -> Option<Arc<Box<dyn SecretKeeper>>> {
        // one-time initialiation of default keepers
        if !registered_defaults().await {
            let mut is = DEFAULTS_REGISTERED.write().await;
            register_default_keepers().await;
            *is = DefaultsRegistered::Registered;
        }

        let klist = KEEPERS.read().await;
        klist
            .iter()
            .find(|k| k.get_scheme() == scheme)
            .map(|k| k.clone())
    }
}

/// returns scheme from uri. e.g., uri_scheme("env:PASSWORD") -> "env"
fn uri_scheme(uri: &str) -> Option<&str> {
    if let Some(cindex) = uri.find(":") {
        if cindex >= 1 {
            return Some(&uri[..cindex]);
        }
    }
    None
}

impl dyn SecretKeeper {
    /// Find keeper for uri
    pub async fn for_uri(uri: &str) -> Result<Arc<Box<Self>>, Error> {
        match uri_scheme(uri) {
            Some(scheme) => match keeper_list::find(scheme).await {
                Some(k) => Ok(k),
                None => Err(Error::KeeperNotFound(String::from(uri))),
            },
            None => Err(Error::InvalidParameter(format!(
                "Invalid keeper uri '{}'",
                uri
            ))),
        }
    }

    /// Register a keeper.
    /// This only fails if uri scheme is missing or not lowercase
    pub async fn register(keeper: Box<dyn SecretKeeper>) -> Result<(), Error> {
        // confirm not registered yet
        let scheme = keeper.get_scheme();
        if scheme.len() == 0 {
            return Err(Error::InvalidParameter(
                "SecretKeeper scheme cannot be empty".to_string(),
            ));
        }
        if scheme.find(char::is_uppercase).is_some() {
            return Err(Error::InvalidParameter(
                "SecretKeeper schemes must be lowewrcase".to_string(),
            ));
        }
        Ok(keeper_list::add(keeper).await?)
    }
}

/// Initialize default keepers
/// If called more than once, no error is generated for the additional calls
async fn register_default_keepers() {
    let env_keeper = Box::new(EnvKeeper::new());
    let rc = SecretKeeper::register(env_keeper).await;
    // this could onlly fail if keeper's uri scheme is invalid (missing or not lowercase)
    debug_assert!(rc.is_ok(), "registering default keepers");
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn scheme_prefix() -> Result<(), Error> {
        assert_eq!(uri_scheme("abc:"), Some("abc"), "simple scheme-only uri");
        assert_eq!(uri_scheme("abc://def"), Some("abc"), "scheme://path");
        assert_eq!(
            uri_scheme("abc:xyz:123:4"),
            Some("abc"),
            "multiple colon separator"
        );

        assert_eq!(
            uri_scheme("attaché:123"),
            Some("attaché"),
            "non-ascii scheme name"
        );
        assert_eq!(uri_scheme("c:"), Some("c"), "single-letter scheme name");

        assert_eq!(uri_scheme("abc"), None, "scheme without : is invalid");
        assert_eq!(uri_scheme(":abc"), None, "scheme must have nonzero length");
        Ok(())
    }

    #[derive(Debug)]
    struct Stub {
        scheme: String,
    }

    #[async_trait]
    impl SecretKeeper for Stub {
        async fn wrap(&self, _uri: &str, _nonce: &[u8], _key: &[u8]) -> Result<WrappedKey, Error> {
            Ok(WrappedKey {
                key_enc: String::from(""),
                key_uri: String::from(""),
                ident: None,
            })
        }
        async fn unwrap(&self, _nonce: &[u8], _wk: &WrappedKey) -> Result<Bytes, Error> {
            Ok(Bytes::new())
        }
        fn get_scheme(&self) -> &str {
            &self.scheme
        }
    }

    #[tokio::test]
    async fn register_validation() -> Result<(), Error> {
        let keeper = Box::new(Stub {
            scheme: String::from(""),
        });
        assert!(
            SecretKeeper::register(keeper).await.is_err(),
            "empty scheme should not allowed"
        );

        let keeper = Box::new(Stub {
            scheme: String::from("test_reg"),
        });
        assert!(
            SecretKeeper::register(keeper).await.is_ok(),
            "register test_reg"
        );

        // cleanup
        keeper_list::remove("test_reg").await;
        Ok(())
    }

    #[tokio::test]
    async fn keeper_list() -> Result<(), Error> {
        assert!(
            SecretKeeper::for_uri("test_first:").await.is_err(),
            "missing keeper should fail"
        );

        let keeper = Box::new(Stub {
            scheme: String::from("test_first"),
        });
        assert!(
            SecretKeeper::register(keeper).await.is_ok(),
            "register first"
        );

        let keeper = Box::new(Stub {
            scheme: String::from("test_second"),
        });
        assert!(
            SecretKeeper::register(keeper).await.is_ok(),
            "register second"
        );

        assert!(
            SecretKeeper::for_uri("test_first:").await.is_ok(),
            "find first"
        );
        assert!(
            SecretKeeper::for_uri("test_second:").await.is_ok(),
            "find second"
        );

        // cleanup
        keeper_list::remove("test_first").await;
        keeper_list::remove("test_second").await;

        assert!(
            SecretKeeper::for_uri("test_first:").await.is_err(),
            "unregister first"
        );
        assert!(
            SecretKeeper::for_uri("test_second:").await.is_err(),
            "unregister second"
        );
        Ok(())
    }
} // mod test
