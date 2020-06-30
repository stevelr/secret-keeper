#[cfg(test)]
mod tests {
    use super::super::{
        decrypt_file, encrypt_file,
        options::{DecryptOptions, EncryptOptions},
        Error,
    };
    use hex;
    use secret_keeper::ciphers::CipherKind;
    use secret_keeper_test_util::{arrays_eq, create_test_file, random_bytes, TestDataKind};

    async fn test_encrypt_file(keeper_uri: &str, cipher: CipherKind) -> Result<(), Error> {
        const TEST_FILE_SIZE: usize = 8192;

        let plain_file = create_test_file(TEST_FILE_SIZE, TestDataKind::PseudoText).await?;
        let fsize = tokio::fs::metadata(&plain_file).await?.len() as usize;
        assert_eq!(fsize, TEST_FILE_SIZE);

        let cipher_file = mktemp::Temp::new_file()?;
        let opt = EncryptOptions {
            keeper_uri: String::from(keeper_uri),
            cipher,
            file: plain_file.as_path().to_str().unwrap().to_string(),
            output: cipher_file.as_path().to_str().unwrap().to_string(),
        };
        encrypt_file(&opt).await?;

        let final_file = mktemp::Temp::new_file()?;
        let opt2 = DecryptOptions {
            keeper_uri: String::from(keeper_uri),
            file: cipher_file.as_path().to_str().unwrap().to_string(),
            output: final_file.as_path().to_str().unwrap().to_string(),
        };
        decrypt_file(&opt2).await?;

        let buf1 = tokio::fs::read(&plain_file).await?;
        let buf2 = tokio::fs::read(&final_file).await?;
        assert_eq!(
            buf1.len(),
            TEST_FILE_SIZE,
            "bytes read actual {} expected {}",
            buf1.len(),
            TEST_FILE_SIZE
        );
        assert!(
            arrays_eq(&buf1, &buf2),
            "encrypt->decrypt->final should be same as original"
        );
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_env_xchacha20() -> Result<(), Error> {
        // passphrase will be 40 random hex characters
        let passphrase = hex::encode(random_bytes(20));

        // unique environment variable name will use part of that
        let env_var = format!("TEST_PASS_{}", &passphrase[..10]);
        let keeper_uri = format!("env:{}", &env_var);
        std::env::set_var(env_var, passphrase);

        test_encrypt_file(&keeper_uri, CipherKind::XChaCha20Poly1305).await?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_env_lz4_xchacha20() -> Result<(), Error> {
        // passphrase will be 40 random hex characters
        let passphrase = hex::encode(random_bytes(20));

        // unique environment variable name will use part of that
        let env_var = format!("TEST_PASS_{}", &passphrase[..10]);
        let keeper_uri = format!("env:{}", &env_var);
        std::env::set_var(env_var, passphrase);

        test_encrypt_file(&keeper_uri, CipherKind::LZ4XChaCha20Poly1305).await?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_env_aes_gcm_256() -> Result<(), Error> {
        // passphrase will be 40 random hex characters
        let passphrase = hex::encode(random_bytes(20));

        // unique environment variable name will use part of that
        let env_var = format!("TEST_PASS_{}", &passphrase[..10]);
        let keeper_uri = format!("env:{}", &env_var);
        std::env::set_var(env_var, passphrase);

        test_encrypt_file(&keeper_uri, CipherKind::AesGcm256).await?;
        Ok(())
    }
}
