//! SecretKeeper for Hashicorp Vault
//! Uses vault's 'transit' engine for encryption and decryption.
//!
//! SecretKeeper uris are of the form
//! - `hashivault://MYKEY`  (uses the default host:port == localhost:8200)
//! - `hashivault://host:port/MYKEY`
//!   - this form uses http for localhost and https for all other hosts
//! - `hashivault:https://host:port/MYKEY`
//!   - this form is only needed if the http/https scheme inferred above is not orrect
//!
//! If host and port are not set in the uri, the VAULT_ADDR is checked.
//! VAULT_ADDR may be defined of the form 'https://127.0.0.1:8200/'.
//! If VAULT_ADDR is not set, 'http://localhost:8200' is used.
//!
//! The REST API urls used to accesss the vault server are of the form:
//!    http(s)://host:port/v1/transit/(encrypt|decrypt|keys)/<KEY_NAME>
//!
//! In the first variation above,
use crate::vault_client::{
    create_key as vault_create_key, decrypt, encrypt, get_base_url, renew_token, ClientSpec,
    URL_SCHEME,
};
use async_trait::async_trait;
use bytes::Bytes;
use secret_keeper::{
    error::{Error, Result},
    keepers::{Create, SecretKeeper},
    util::form_get,
    WrappedKey,
};
use serde_urlencoded;
use std::env;

/// HashivaultKeeper - hashicorp vault
#[derive(Debug)]
pub struct HashivaultKeeper {}

/// Options for initializing HashivaultKeeper
pub struct HashivaultOptions<'s> {
    /// If the vault token is periodic, the server can auto-renew the token
    /// at the time keeper is constructed. It does not auto-renew during runtime,
    /// so you must ensure that the token ttl is either unlimited, or at least
    /// as long as the expected runtime of the keeper.
    /// The token to be renewed is specified either with the "?token=" parameter
    /// of initial_uri, or in the environment variable VAULT_TOKEN
    pub renew_on_start: bool,

    /// The URI provided in opts is only currently used for initialization,
    /// and, only if renew_on_start is true.
    /// If rewnew_on_start is true, the vault server address must be provided
    /// either in the initial_uri OR in the environment variable VAULT_ADDR
    /// It is ignored for wrap and unwrap calls, in favor of the uri passed
    /// to those functions.
    pub initial_uri: &'s str,
}

impl<'o> HashivaultOptions<'o> {
    pub fn defaults() -> Self {
        HashivaultOptions {
            renew_on_start: false,
            initial_uri: "",
        }
    }
}

impl HashivaultKeeper {
    /// Constructs a new hashivault keeper with default options
    pub async fn new_default() -> Result<Self, Error> {
        Ok(Self::new(HashivaultOptions::defaults()).await?)
    }

    /// Constructs a new hashivault keeper
    pub async fn new(opt: HashivaultOptions<'_>) -> Result<Self, Error> {
        if opt.renew_on_start {
            let spec = ClientSpec::from_uri(opt.initial_uri)?;
            renew_token(&spec).await?;
        }
        Ok(HashivaultKeeper {})
    }

    /// register with SecretKeeper so it can be discovered with SecretKeeper::for_uri
    pub async fn register(self) -> Result<(), Error> {
        Ok(SecretKeeper::register(Box::new(self)).await?)
    }
}

#[async_trait]
impl SecretKeeper for HashivaultKeeper {
    /// Sends key to hashicorp vault to be encrypted.
    /// key-encryption-key never leavs the Hashicorp vault.
    /// Returned encrypted key is a string
    async fn wrap(&self, uri: &str, _nonce: &[u8], key: &[u8]) -> Result<WrappedKey, Error> {
        // nonce isn't used, but vault generates new nonce per key,
        // so same key encrypted for different files will still be different
        let spec = ClientSpec::from_uri(uri)?;
        let val = encrypt(&spec, key).await?;
        Ok(WrappedKey {
            key_enc: val,
            key_uri: String::from(uri),
            ident: None,
        })
    }

    /// Sends key to hashicorp vault to be decrypted.
    /// key-encryption-key never leavs the Hashicorp vault.
    async fn unwrap(&self, _nonce: &[u8], wk: &WrappedKey) -> Result<Bytes, Error> {
        let spec = ClientSpec::from_uri(&wk.key_uri)?;
        let plaintext = decrypt(&spec, wk.key_enc.clone()).await?;
        Ok(Bytes::from(plaintext.to_owned()))
    }

    /// Returns the scheme 'hashivault'
    fn get_scheme(&self) -> &str {
        URL_SCHEME
    }

    /// Returns instance of Create
    fn as_create(&self) -> Result<&dyn Create, Error> {
        Ok(self)
    }
}

#[async_trait]
impl Create for HashivaultKeeper {
    /// Creates the key.
    /// `key_name` is any valid key name
    /// `params` are url-encoded parameters that can be created with
    /// [`serde_urlencoded`](https://docs.rs/serde_urlencoded/0.6.1/serde_urlencoded/fn.to_string.html)
    ///
    /// Params:
    ///   - 'key_type' type of key (see vault documentation). If not specified, uses "aes256-gcm96".
    ///   - 'token' vault auth token. If not specified, uses value from env variable VAULT_TOKEN.
    ///   - 'addr' vault address. If not specified, uses value from env variable VAULT_ADDR.
    ///
    /// For the code sample below to work,
    /// you need VAULT_ADDR and VAULT_TOKEN set in environment and vault server running.
    /// ```
    /// use secret_keeper::keepers::Create;
    /// use secret_keeper_hashivault::{HashivaultKeeper, HashivaultOptions};
    /// # use tokio_test;
    /// # tokio_test::block_on( async {
    /// // create 256-bit AES-GCM key in hashivault
    /// let params = [ ("key_type", "aes256-gcm96") ];
    /// let key_name = "my-super-secret-key";
    /// let keeper = HashivaultKeeper::new(HashivaultOptions::defaults()).await
    ///              .expect("hashivault constructor");
    /// let form = serde_urlencoded::to_string(&params).expect("invalid param syntax");
    /// let _ = keeper.create_key(key_name, &form).await.expect("create key error");
    /// # });
    /// ```
    async fn create_key(&self, key_name: &str, params: &str) -> Result<(), Error> {
        let fields = serde_urlencoded::from_str(params).map_err(|e| {
            Error::InvalidParameter(format!("'params' is not valid urlencoded: {}", e))
        })?;
        let base_url = form_get(&fields, "addr")
            .unwrap_or(&get_base_url())
            .to_string();
        let token = form_get(&fields, "token")
            .map(|s| s.to_string())
            .unwrap_or(
            match env::var("VAULT_TOKEN") {
                Ok(t) => t,
                Err(_) => {
                    return Err(Error::InvalidParameter(
                        "token required: either set 'token' in params, or set VAULT_TOKEN in environment".to_string()));
                }
            }
        );
        let key_type = form_get(&fields, "key_type").unwrap_or("aes256-gcm96");

        let spec = ClientSpec {
            uri: "".to_string(), // not used
            base_url,
            token,
            key_name: key_name.to_string(),
        };
        let _ = vault_create_key(&spec, key_type).await?;
        Ok(())
    }
}
