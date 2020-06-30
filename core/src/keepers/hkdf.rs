//! Key derivation functions used by env and prompt SecretKeepers

use crate::{
    ciphers::{
        aesgcm256::{AesGcm256, NONCEBYTES as AES_NONCEBYTES},
        xchacha20::{XChaCha20, KEYBYTES, NONCEBYTES as XCHACHA20_NONCEBYTES},
        Cipher, CipherKind,
    },
    error::{Error, Result},
    util,
};
use hmac::Hmac;
use pbkdf2;
use sha2::Sha256;

/// Number of rounds for password generation.
/// More rounds takes longer for an attacker to brute-force guess any password.
/// ROUNDS may not change after deployment to ensure binary compatibility of vaults,
/// unless an upgrade/reencryption option is provided.
const ROUNDS: u32 = 20000;

/// This randomly-generated context (aka "salt") is unique to this application,
/// and must remain constant to ensure binary compatibility of vaults.
const CONTEXT: &str = "!*<(q|;J$#R,h?4*V[Xp&y@^wgt+MWL9@nFgL%qqXmfJW;>g}k;Rbpvj=3.";

/// Create a cipher from the kdf-derived key (aka, the key-encryption-key)
/// Uses PBKDF2+HMAC+SHA256+SALT (from [RustCrypto](https://github.com/RustCrypto/password-hashes))
/// The nonce must be at least as long as required by the cipher algorithm.
/// (24 bytes for the default XChaCha20-Poly1305, 12 for AesGcm256)
pub fn key_cipher_from_pass(
    passphrase: &str,
    nonce: &[u8],
    alg: CipherKind,
) -> Result<Box<dyn Cipher>, Error> {
    let derived_key: Vec<u8> = key_from_pass(passphrase, nonce);
    let cipher: Box<dyn Cipher> = match alg {
        CipherKind::XChaCha20Poly1305 => Box::new(
            XChaCha20::init_from(&derived_key, &nonce[..XCHACHA20_NONCEBYTES]).map_err(|e| {
                Error::OtherError(
                    format!("bad nonce or hkdf key from env keeper: {:?}", e).to_string(),
                )
            })?,
        ),
        CipherKind::AesGcm256 => Box::new(
            AesGcm256::init_from(&derived_key, &nonce[..AES_NONCEBYTES]).map_err(|e| {
                Error::OtherError(
                    format!("bad nonce or hkdf key from env keeper: {:?}", e).to_string(),
                )
            })?,
        ),
        _ => return Err(Error::InvalidParameter("Unsupported algorithm".to_string())),
    };
    Ok(cipher)
}

/// Generate key from passphrase.
/// This function is not public because keys should always be wrapped (encrypted).
/// to reduce risk of accidental logging or exposure.
/// For purposes of this function, nonce can be arbitrary length.
fn key_from_pass(passphrase: &str, nonce: &[u8]) -> Vec<u8> {
    let mut derived = util::uninitialized_vec(KEYBYTES);
    let mut pass = String::from(CONTEXT);
    pass.push_str(passphrase);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(&pass.as_bytes(), nonce, ROUNDS, &mut derived);
    derived
}

#[cfg(test)]
mod test {

    use super::{key_cipher_from_pass, key_from_pass};
    use crate::{
        ciphers::{
            aesgcm256, xchacha20,
            CipherKind::{AesGcm256, XChaCha20Poly1305},
        },
        error::{Error, Result},
    };
    use hex;
    use secret_keeper_test_util::{arrays_eq, random_bytes};

    #[test]
    // (pass + nonce) generates key+cipher, cipher encrypts & decrypts
    fn kdf_works_xchacha() -> Result<(), Error> {
        let nonce = random_bytes(xchacha20::NONCEBYTES);

        let pass = hex::encode(random_bytes(24));

        // generates a functional cipher with no errors
        let cipher = key_cipher_from_pass(&pass, &nonce, XChaCha20Poly1305)?;
        assert_eq!(
            cipher.nonce_len(),
            xchacha20::NONCEBYTES,
            "xchacha20_poly1305 from pass"
        );
        Ok(())
    }

    #[test]
    // (pass + nonce) generates key+cipher, cipher encrypts & decrypts
    // use longer nonce (24B) of XChaCha20-Poly1305
    fn kdf_works_aes() -> Result<(), Error> {
        let nonce = random_bytes(xchacha20::NONCEBYTES);

        let pass = hex::encode(random_bytes(24));

        // generates a functional cipher with no errors
        let cipher = key_cipher_from_pass(&pass, &nonce, AesGcm256)?;
        assert_eq!(
            cipher.nonce_len(),
            aesgcm256::NONCEBYTES,
            "aesgcm256 key from pass"
        );

        Ok(())
    }

    #[tokio::test]
    // (pass + nonce) generates key+cipher, cipher encrypts & decrypts
    async fn kdf_end_to_end_xchacha() -> Result<(), Error> {
        let nonce = random_bytes(xchacha20::NONCEBYTES);

        let pass = hex::encode(random_bytes(24));

        // generates a functional cipher
        let cipher = key_cipher_from_pass(&pass, &nonce, XChaCha20Poly1305)?;
        assert_eq!(cipher.nonce_len(), xchacha20::NONCEBYTES);

        // encrypt and decrypt string
        let plaintext = random_bytes(100);
        let ciphertext = cipher.seal(plaintext.as_ref(), None).await?;
        let pt = cipher.open(&ciphertext, None).await?;
        assert!(
            arrays_eq(plaintext.as_ref(), &pt),
            "encrypt-decrypt, before == after"
        );
        assert!(
            !arrays_eq(plaintext.as_ref(), &ciphertext),
            "plaintext != ciphertext"
        );
        Ok(())
    }

    #[tokio::test]
    // (pass + nonce) generates key+cipher, cipher encrypts & decrypts
    async fn kdf_end_to_end_aes() -> Result<(), Error> {
        let nonce = random_bytes(aesgcm256::NONCEBYTES);

        let pass = hex::encode(random_bytes(24));

        // generates a functional cipher
        let cipher = key_cipher_from_pass(&pass, &nonce, AesGcm256)?;
        assert_eq!(cipher.nonce_len(), aesgcm256::NONCEBYTES);

        // encrypt and decrypt string
        let plaintext = random_bytes(100);
        let ciphertext = cipher.seal(plaintext.as_ref(), None).await?;
        let pt = cipher.open(&ciphertext, None).await?;
        assert!(
            arrays_eq(plaintext.as_ref(), &pt),
            "encrypt-decrypt, before == after"
        );
        assert!(
            !arrays_eq(plaintext.as_ref(), &ciphertext),
            "plaintext != ciphertext"
        );
        Ok(())
    }

    #[test]
    // test that same password + same nonce reproduces same key
    fn kdf_repeatability() -> Result<(), Error> {
        let nonce = random_bytes(xchacha20::NONCEBYTES);

        let pass1 = hex::encode(random_bytes(40));
        let key1 = key_from_pass(&pass1, &nonce);
        let key2 = key_from_pass(&pass1, &nonce);

        assert!(
            arrays_eq(&key1, &key2),
            "same pw+nonce should always generate same key"
        );
        Ok(())
    }

    #[test]
    // test that same password + different nonce makes different key
    fn kdf_uniqueness() -> Result<(), Error> {
        let mut nonce = random_bytes(xchacha20::NONCEBYTES);

        let pass1 = hex::encode(random_bytes(40));
        let key1 = key_from_pass(&pass1, &nonce);

        // change one bit of nonce
        nonce[0] = nonce[0] ^ 128u8;
        let key2 = key_from_pass(&pass1, &nonce);
        assert!(!arrays_eq(&key1, &key2), "new nonce makes new key");

        // change it back, re-process
        nonce[0] = nonce[0] ^ 128u8;
        let key3 = key_from_pass(&pass1, &nonce);
        assert!(arrays_eq(&key1, &key3), "consistent key1 == key3");

        Ok(())
    }
}
