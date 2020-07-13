#[cfg(test)]
mod tests {

    use crate::{
        ciphers::{xchacha20::NONCEBYTES, CipherKind},
        error::{Error, Result},
        keepers::SecretKeeper,
        rand,
    };

    const KEEPER_URI: &str = "env:PASSPHRASE";
    const PLAINTEXT: &[u8] = b"hello world!";
    const CIPHER: CipherKind = CipherKind::XChaCha20Poly1305;

    #[tokio::test]
    async fn simple() -> Result<(), Error> {
        // set passphrase in environment so the example runs w/o interaction
        std::env::set_var("PASSPHRASE", "zSF5gkEcuWn4jZgZRxwH");

        // Sender
        let mut nonce = [0u8; NONCEBYTES];
        rand::fill_buf(&mut nonce)?;
        let keeper = SecretKeeper::for_uri(KEEPER_URI).await?;
        let cipher = keeper.init_cipher(CIPHER, &nonce, None).await?;
        let buf = cipher.seal(PLAINTEXT, None).await?;
        let envelope = cipher.export(KEEPER_URI, &nonce, &keeper).await?;

        // envelope contains the keeper_uri and the encrypted key
        // to decrypt 'buf', a recipient needs envelope and nonce
        // (and of course, agreement on the cipher algorithm)

        // Reciever
        let keeper = SecretKeeper::for_uri(&envelope.key_uri).await?;
        let cipher = keeper.init_cipher(CIPHER, &nonce, Some(&envelope)).await?;
        let result = cipher.open(&buf, None).await?;

        assert_eq!(&result, PLAINTEXT);
        Ok(())
    }
}
