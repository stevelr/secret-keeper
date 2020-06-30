#[cfg(test)]
mod tests {

    use crate::{
        ciphers::{xchacha20_comp::XChaCha20Compress, Cipher, CompressingCipher},
        error::{Error, Result},
        util::uninitialized_vec,
    };
    use bytes::BytesMut;
    use hex;
    use secret_keeper_test_util::{arrays_eq, random_bytes};
    use std::cmp::min;

    const DATA_SIZE: usize = 20;

    //
    // Note most of the tests of impl Cipher are in test_cipher.
    // This file contains tests specific to Compressing cipher
    //

    fn printbuf(b: &[u8], name: &str) -> () {
        let nbytes = min(40, b.len());
        println!("{}: {}", name, hex::encode(&b[..nbytes]));
    }

    #[tokio::test]
    async fn test_init() -> Result<(), Error> {
        let cipher: XChaCha20Compress = XChaCha20Compress::init()?;
        println!("Dumping cipher:\n{:?}", cipher);
        Ok(())
    }

    #[tokio::test]
    async fn seal_compressed() -> Result<(), Error> {
        let cipher: XChaCha20Compress = XChaCha20Compress::init()?;
        printbuf(cipher.get_nonce(), "nonce");

        // generate buffer and make backup copy since it will be modified
        let mut plaintext = random_bytes(DATA_SIZE);
        let mut backup = uninitialized_vec(DATA_SIZE);
        backup.copy_from_slice(&plaintext);

        printbuf(&plaintext, "sod plain ");
        printbuf(&backup, "sod backup");
        assert!(arrays_eq(&plaintext, &backup));

        let (data, tag) = cipher.seal_compressed(&mut plaintext, None).await?;
        assert!(!arrays_eq(&data.as_ref(), &backup));

        let mut mdata = BytesMut::from(data.as_ref());
        let uncomp = cipher
            .open_compressed(&mut mdata, &tag.0, None, None)
            .await?;
        assert!(arrays_eq(&uncomp.as_ref(), &backup));

        Ok(())
    }
}
