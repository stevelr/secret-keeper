//! EnvKeeper - derives key from environment variable

use crate::{
    ciphers::{Cipher, CipherKind},
    error::{Error, Result},
    keepers::{hkdf::key_cipher_from_pass, SecretKeeper},
    util::{FromBech32, ToBech32},
    WrappedKey,
};

use async_trait::async_trait;
use bytes::Bytes;
use std::env;
use url::Url;

/// Default variable name to be used if var not specified in the keeper uri
const ENV_VAR_NAME: &str = "VAULT_PASSWORD";
/// EnvKeeper uri is "env:", or "env://VARNAME" to use a custom environment variable.
const SCHEME: &str = "env";

/// Note that while _content_ encryption can use any implemented Cipher,
/// the env and prompt keepers need a Cipher for encrypting the key
/// (other keepers such as hashivault and cloudkms use the external service
/// to perform the key encryption)
/// For this, we prefer XChaCha20Poly1305 because of its longer nonce.
const ENV_KEEPER_CIPHER: CipherKind = CipherKind::XChaCha20Poly1305;

/// EnvKeeper generates encryption key from a passphrase in environment variable.
///
/// The passphrase from the environment is combined wih a nonce plus salt
/// through PBKDF2+HMAC+SHA256 to generate the key.
/// (Implementation by [RustCrypto](https://github.com/RustCrypto/password-hashes))
///
/// Uri formats:
/// - `env:` uses the default environment variable `VAULT_PASSWORD`
/// - `env:VARNAME` - variable `VARNAME` contains the passphrase
/// - `env://VARNAME` - alternate syntax
///
#[derive(Debug)]
pub struct EnvKeeper {}

impl EnvKeeper {
    pub fn new() -> Self {
        EnvKeeper {}
    }
}

#[async_trait]
impl SecretKeeper for EnvKeeper {
    /// returns the uri scheme
    fn get_scheme(&self) -> &str {
        SCHEME
    }

    /// Encrypts key with a passphrase-generated key
    /// Passphrase is retrieved from enviornment variable (default VAULT_PASSWORD,
    /// or the name in the key uri "env:<VAR_NAME>").
    /// Returned encrypted key is stringified with bech32.
    /// Applications using envelope encryption don't call this function directly,
    /// but instead use Cipher.export. Cipher.export invokes SecretKeeper.wrap
    /// to encrypt the key and generate the WrappedKey.
    ///
    async fn wrap(&self, uri: &str, nonce: &[u8], key: &[u8]) -> Result<WrappedKey, Error> {
        let key_cipher = make_key_cipher(uri, nonce, ENV_KEEPER_CIPHER)?;
        let encrypted = key_cipher.seal(key, None).await?;
        Ok(WrappedKey {
            key_enc: encrypted.to_bech32(),
            key_uri: String::from(uri),
            ident: None,
        })
    }

    /// Unwraps and decrypts key with a passphrase-generated key
    /// Passphrase is retrieved from enviornment variable (default VAULT_PASSWORD,
    /// or the name in the key uri "env:<VAR_NAME>").
    async fn unwrap(&self, nonce: &[u8], wk: &WrappedKey) -> Result<Bytes, Error> {
        let key_cipher = make_key_cipher(&wk.key_uri, nonce, ENV_KEEPER_CIPHER)?;
        let mut encrypted = (&wk.key_enc).from_bech32()?;
        key_cipher.open(&mut encrypted, None).await
    }
}

/// lookup environment variable name from the uri
fn get_varname(uri: &str) -> Result<String, Error> {
    let url = Url::parse(uri).map_err(|e| {
        Error::InvalidParameter(format!(
            "Invalid uri. Should be 'env://VAR' or 'env:': {}",
            e
        ))
    })?;
    if url.scheme() != SCHEME {
        return Err(Error::InvalidParameter(
            "Invalid scheme for env keeper. Uri should begin with 'env:'".to_string(),
        ));
    }

    Ok(match url.host_str() {
        // "env://foo" -> (host:Some("foo"), path: "")
        // "env://foo/bar" -> (host:Some("foo"), path:"/bar")
        Some(host) => host,

        None => {
            if url.path() != "" {
                // (alt syntax) "env:foo" -> (host:None, path:"foo")
                url.path()
            } else {
                // "env:" - use default variable name
                ENV_VAR_NAME
            }
        }
    }
    // we could save one string alloc by doing the env::var lookup here
    // and returning the passphrase, but keeping this fn specific to url parsing
    // makes it easier to test.
    .to_string())
}

/// create the key using hkdf and passphrase, and initialize Cipher with key
fn make_key_cipher(uri: &str, nonce: &[u8], alg: CipherKind) -> Result<Box<dyn Cipher>, Error> {
    // detemine variable name from uri
    // error thrown here if uri is malformed
    let varname = get_varname(uri)?;
    // look up variable in environment
    // error here if env var not defined
    let passphrase = env::var(&varname).map_err(|_| Error::MissingEnv(varname))?;
    // use hkdf to turn passphrase into key and initialize cipher
    key_cipher_from_pass(&passphrase, nonce, alg)
}

#[cfg(test)]
mod test {

    use super::{get_varname, make_key_cipher, EnvKeeper, ENV_VAR_NAME};
    use crate::{
        ciphers::{xchacha20, CipherKind},
        error::{Error, Result},
        keepers::SecretKeeper,
    };
    use secret_keeper_test_util::{arrays_eq, random_bytes};
    use std::env;

    #[test]
    fn varname() -> Result<(), Error> {
        assert!(get_varname("").is_err(), "empty uri");
        assert!(get_varname("abc").is_err(), "no scheme");
        assert!(get_varname("env").is_err(), "no colon after scheme");
        assert_eq!(get_varname("env:").expect("default"), ENV_VAR_NAME);
        assert_eq!(get_varname("env:foo").expect("env:var"), "foo");
        assert_eq!(get_varname("env://foo").expect("env://var"), "foo");
        assert_eq!(get_varname("env://foo/bar").expect("env://var/path"), "foo");
        Ok(())
    }

    #[test]
    fn env_constructor() {
        let k = EnvKeeper::new();
        assert_eq!(k.get_scheme(), "env", "env keeper scheme");
    }

    #[tokio::test]
    async fn env_register() -> Result<(), Error> {
        let k = SecretKeeper::for_uri("env:").await;
        assert!(k.is_ok(), "find keeper for uri env:");
        Ok(())
    }

    #[tokio::test]
    /// verify make_key_cipher returns cipher
    async fn mk_cipher_xchacha() -> Result<(), Error> {
        let nonce = random_bytes(xchacha20::NONCEBYTES);
        // env variable name used for this test
        const TEST_VAR: &str = "test_make_cipher_c5f20e131d04";
        let env_uri: String = format!("env:{}", TEST_VAR);

        // make_key_cipher should fail if the env var is undefined
        let should_fail = make_key_cipher(&env_uri, &nonce, CipherKind::XChaCha20Poly1305);
        assert!(should_fail.is_err());

        // define the variable with a passphrase
        env::set_var(TEST_VAR, "my-secret-unguessable-passphrase");

        let cipher = make_key_cipher(&env_uri, &nonce, CipherKind::XChaCha20Poly1305)?;
        assert_eq!(
            cipher.nonce_len(),
            xchacha20::NONCEBYTES,
            "cipher sanity check"
        );
        // clear after test
        env::remove_var(TEST_VAR);
        Ok(())
    }

    #[tokio::test]
    /// fetch phrase from environment, and wrap and unwrap using the keeper api
    async fn wrap_unwrap() -> Result<(), Error> {
        // name of environment variable holding passphrase
        const VAR_NAME: &str = "TEST_ENVKEEPER_WRAP_UNWRAP";
        let mut uri: String = String::from("env://");
        uri.push_str(VAR_NAME);

        let rand_phrase = hex::encode(random_bytes(24));
        env::set_var(VAR_NAME, rand_phrase);

        let keeper = SecretKeeper::for_uri(&uri).await?;

        let key = random_bytes(xchacha20::KEYBYTES);
        let nonce = random_bytes(xchacha20::NONCEBYTES);

        let wrapped = keeper.wrap(&uri, &nonce, &key).await?;

        let unwrapped = keeper.unwrap(&nonce, &wrapped).await?;

        assert!(
            arrays_eq(&key, &unwrapped.as_ref()),
            "cipher wrap & unwrap ok"
        );
        Ok(())
    }
}
