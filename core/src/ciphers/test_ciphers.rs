/// tests for ciphers
/// (either nacl or pure)
///
///
#[cfg(test)]
mod tests {

    use crate::{
        ciphers::{
            aesgcm256::AesGcm256,
            xchacha20::{XChaCha20, NONCEBYTES, TAGBYTES},
            xchacha20_comp::XChaCha20Compress,
            Cipher, CipherKind,
        },
        error::{Error, Result},
        keepers::SecretKeeper,
        util::{uninitialized_bytes, uninitialized_vec},
    };
    use bytes::Bytes;
    use random_fast_rng::FastRng;
    use secret_keeper_test_util::{arrays_eq, random_bytes, random_fill_text};
    use std::borrow::Borrow;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::fs::File;

    const DATA_SIZE: usize = 1024;

    // check all the supported names for string -> CipherKind lookup
    fn check_variants(k: CipherKind, names: Vec<&str>) -> Result<(), Error> {
        // the first one is the to_string representation
        assert_eq!(names[0], k.to_string());

        for name in names {
            assert_eq!(CipherKind::from_str(name)?, k);
        }

        Ok(())
    }

    #[test]
    fn kind_string() -> Result<(), Error> {
        check_variants(
            CipherKind::AesGcm256,
            vec!["AesGcm256", "aes", "aesgcm256", "aesgcm"],
        )?;
        check_variants(
            CipherKind::XChaCha20Poly1305,
            vec!["XChaCha20Poly1305", "xchacha20poly1305", "xchacha20"],
        )?;
        check_variants(
            CipherKind::LZ4XChaCha20Poly1305,
            vec![
                "LZ4XChaCha20Poly1305",
                "lz4xchacha20poly1305",
                "lz4xchacha20",
                "lz4",
            ],
        )?;
        Ok(())
    }

    #[test]
    fn tag_size() {
        // as defined by the ietf specification
        assert_eq!(TAGBYTES, 16);
    }

    async fn seal_open(cipher: Box<dyn Cipher>) -> Result<(), Error> {
        let plaintext = random_bytes(DATA_SIZE);

        let enc = cipher.seal(&plaintext, None).await?;
        let dec = cipher.open(enc.borrow(), None).await?;
        assert!(arrays_eq(&plaintext, &dec.borrow()));
        Ok(())
    }

    async fn with_aad(cipher: Box<dyn Cipher>) -> Result<(), Error> {
        if cipher.supports_aad() {
            // same aad works
            let aad_one: Bytes = Bytes::from("signature");
            let plaintext = random_bytes(DATA_SIZE);

            let enc = cipher.seal(&plaintext, Some(&aad_one)).await?;
            let dec = cipher.open(&enc.borrow(), Some(&aad_one)).await?;
            assert!(arrays_eq(&plaintext, &dec.borrow()), "encryption with aad");

            let aad_two: Bytes = Bytes::from("happy birthday");

            let resp = cipher.open(&enc, Some(&aad_two)).await;
            assert!(resp.is_err(), "different aad expected to fail");
        } else {
            println!("Skipping test with_aad because cipher doesn't support it");
        }
        Ok(())
    }

    async fn seal_open_detached(cipher: Box<dyn Cipher>) -> Result<(), Error> {
        // generate buffer and make backup copy since it will be modified
        let mut plaintext = random_bytes(DATA_SIZE);
        let mut backup = uninitialized_vec(DATA_SIZE);
        backup.copy_from_slice(&plaintext);

        assert!(arrays_eq(&plaintext, &backup));

        let tag = cipher.seal_detached(&mut plaintext, None).await?;
        assert!(!arrays_eq(&plaintext, &backup));

        let _ = cipher.open_detached(&mut plaintext, &tag.0, None).await?;
        assert!(arrays_eq(&plaintext, &backup));
        Ok(())
    }

    async fn file_seal_unseal(cipher: Box<dyn Cipher>) -> Result<(), Error> {
        const BUF_LEN: usize = 4096;
        let mut rng = FastRng::new();

        let mut word_buf = uninitialized_bytes(BUF_LEN);
        random_fill_text(&mut rng, &mut word_buf);

        let mut copy_buf = uninitialized_bytes(BUF_LEN);
        copy_buf.copy_from_slice(&word_buf);

        let fpath = mktemp::Temp::new_path();
        let mut test_out = File::create(&fpath).await?;
        let (tag, sz) = cipher
            .seal_write(&mut word_buf, &mut test_out, None)
            .await?;

        let mut test_in = File::open(&fpath).await?;
        let read_len = test_in.metadata().await?.len();

        println!(
            "file_seal_unseal name:{:?}, size:{}, disk_size:{}",
            &fpath.to_path_buf(),
            BUF_LEN,
            read_len
        );
        assert_eq!(
            sz,
            read_len,
            "file {:?} size reported by seal_write {} should match size on disk {}",
            &fpath.to_path_buf(),
            sz,
            read_len
        );
        let read_buf = cipher
            .open_read(
                &mut test_in,
                sz,
                Some(BUF_LEN as u64),
                tag.get_slice(),
                None,
            )
            .await?;
        assert_eq!(
            BUF_LEN,
            read_buf.len(),
            "expected to read {} actual {}",
            BUF_LEN,
            read_buf.len()
        );
        assert!(arrays_eq(read_buf.as_ref(), copy_buf.as_ref()));

        Ok(())
    }

    async fn make_test_keeper() -> Result<(Vec<u8>, Arc<Box<dyn SecretKeeper>>), Error> {
        let nonce = random_bytes(NONCEBYTES);
        // env variable name used for this test
        const TEST_VAR: &str = "test_make_cipher_9987bd855ad6";
        let env_uri: String = format!("env:{}", TEST_VAR);
        // define the variable with a passphrase
        std::env::set_var(TEST_VAR, "my-secret-unguessable-passphrase");
        let keeper = SecretKeeper::for_uri(&env_uri).await?;
        Ok((nonce.to_vec(), keeper))
    }

    // leaving these as separate functions makes it easier
    // to select different cipers or specific tests from 'cargo test' command line

    //
    // ------ xchacha20
    //

    #[tokio::test]
    async fn init_xchacha20() -> Result<(), Error> {
        let (nonce, keeper) = make_test_keeper().await?;
        let cipher = keeper
            .init_cipher(CipherKind::XChaCha20Poly1305, &nonce, None)
            .await?;
        assert!(arrays_eq(&nonce[..cipher.nonce_len()], cipher.get_nonce()));
        Ok(())
    }

    #[tokio::test]
    async fn seal_open_xchacha20() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20::init()?);
        let _ = seal_open(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn with_aad_xchacha20() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20::init()?);
        let _ = with_aad(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn seal_open_detached_xchacha20() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20::init()?);
        let _ = seal_open_detached(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn file_seal_write_open_read_xchacha20() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20::init()?);
        let _ = file_seal_unseal(cipher).await?;
        Ok(())
    }

    //
    // ------ xchacha20_compressed
    //

    #[tokio::test]
    async fn init_xchacha20_comp() -> Result<(), Error> {
        let (nonce, keeper) = make_test_keeper().await?;
        let cipher = keeper
            .init_cipher(CipherKind::LZ4XChaCha20Poly1305, &nonce, None)
            .await?;
        assert!(arrays_eq(&nonce[..cipher.nonce_len()], cipher.get_nonce()));
        Ok(())
    }

    #[tokio::test]
    async fn seal_open_xchacha20_comp() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20Compress::init()?);
        let _ = seal_open(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn with_aad_xchacha20_comp() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20Compress::init()?);
        let _ = with_aad(cipher).await?;
        Ok(())
    }

    // TODO: Temporarily disabled - seal_open_detached isn't implemented for comp cipher yet
    //#[tokio::test]
    //async fn seal_open_detached_xchacha20_comp() -> Result<(), Error> {
    //    let cipher = Box::new(XChaCha20Compress::init()?);
    //    let _ = seal_open_detached(cipher).await?;
    //    Ok(())
    //}

    #[tokio::test]
    async fn file_seal_write_open_read_xchacha20_comp() -> Result<(), Error> {
        let cipher = Box::new(XChaCha20Compress::init()?);
        let _ = file_seal_unseal(cipher).await?;
        Ok(())
    }

    //
    // ------ aes_256_gcm
    //

    #[tokio::test]
    async fn init_aesgcm256() -> Result<(), Error> {
        let (nonce, keeper) = make_test_keeper().await?;
        let cipher = keeper
            .init_cipher(CipherKind::AesGcm256, &nonce, None)
            .await?;
        assert!(arrays_eq(&nonce[..cipher.nonce_len()], cipher.get_nonce()));
        Ok(())
    }

    #[tokio::test]
    async fn seal_open_aesgcm256() -> Result<(), Error> {
        let cipher = Box::new(AesGcm256::init()?);
        let _ = seal_open(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn with_aad_aesgcm256() -> Result<(), Error> {
        let cipher = Box::new(AesGcm256::init()?);
        let _ = with_aad(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn seal_open_detached_aesgcm256() -> Result<(), Error> {
        let cipher = Box::new(AesGcm256::init()?);
        let _ = seal_open_detached(cipher).await?;
        Ok(())
    }

    #[tokio::test]
    async fn file_seal_write_open_read_aesgcm256() -> Result<(), Error> {
        let cipher = Box::new(AesGcm256::init()?);
        let _ = file_seal_unseal(cipher).await?;
        Ok(())
    }
}
