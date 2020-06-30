use crate::term::{get_password, get_password_with_confirm};
use async_trait::async_trait;
use bytes::Bytes;
use secret_keeper::{
    ciphers::CipherKind,
    error::{Error, Result},
    keepers::{hkdf::key_cipher_from_pass, SecretKeeper},
    util::{FromBech32, ToBech32},
    WrappedKey,
};

const PROMPT_NEW_VAULT_PASS: &str = "New Vault Password: ";
const PROMPT_VAULT_PASS: &str = "Vault Password: ";
const PROMPT_CONFIRM: &str = "Confirm: ";

/// PromptKeeper
/// Uses secret passphrase defined in environment.
/// Default variable name is "VAULT_PASSWORD"
#[derive(Debug)]
pub struct PromptKeeper {}

const SCHEME: &str = "prompt";
const KEEPER_URI: &str = "prompt:";

/// Note that while _content_ encryption can use any implemented Cipher,
/// the env and prompt keepers need a Cipher for encrypting the key
/// (other keepers such as hashivault and cloudkms use the external service
/// to perform the key encryption)
/// For this, we prefer XChaCha20Poly1305 because of its longer nonce.
const PROMPT_CIPHER: CipherKind = CipherKind::XChaCha20Poly1305;

fn get_passphrase(create: bool) -> Result<String, Error> {
    match match create {
        true => get_password_with_confirm(PROMPT_NEW_VAULT_PASS, PROMPT_CONFIRM),
        false => get_password(PROMPT_VAULT_PASS),
    } {
        Some(p) => Ok(p),
        // in case of None, error has already been printed (Cancelled or Didn't match)
        None => Err(Error::OtherError("Invalid password".to_string())),
    }
}

impl PromptKeeper {
    /// creates a prompt keeper with default options
    pub fn new_default() -> Self {
        Self {}
    }

    /// register with SecretKeeper so it can be discovered with SecretKeeper::for_uri
    pub async fn register(self) -> Result<(), Error> {
        Ok(SecretKeeper::register(Box::new(self)).await?)
    }
}

#[async_trait]
impl SecretKeeper for PromptKeeper {
    /// Returns uri used to initialize this keeper
    fn get_scheme(&self) -> &str {
        SCHEME
    }

    /// Encrypts key with a passphrase-generated key
    /// Returned encrypted key is stringified with bech32.
    async fn wrap(&self, _uri: &str, nonce: &[u8], key: &[u8]) -> Result<WrappedKey, Error> {
        let pass = get_passphrase(true)?;
        let key_cipher = key_cipher_from_pass(&pass, nonce, PROMPT_CIPHER)?;
        let encrypted = key_cipher.seal(key, None).await?;
        Ok(WrappedKey {
            key_enc: encrypted.to_bech32(),
            key_uri: String::from(KEEPER_URI),
            ident: None,
        })
    }

    /// Unwraps and decrypts key with a passphrase-generated key
    async fn unwrap(&self, nonce: &[u8], wk: &WrappedKey) -> Result<Bytes, Error> {
        let pass = get_passphrase(false)?;
        let key_cipher = key_cipher_from_pass(&pass, nonce, PROMPT_CIPHER)?;
        let mut encrypted = (&wk.key_enc).from_bech32()?;
        key_cipher.open(&mut encrypted, None).await
    }
}

#[cfg(test)]
mod test {

    // TODO: where are the tests???
}
