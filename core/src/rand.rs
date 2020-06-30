//! CSRNG based on platform (OS) CSRNG.
//!
//! The function below is used for nonce generation, and for key generation for some SecretKeepers.
//! For SecretKeepers such as Hashivault and CloudKMS, keys are generated
//! by those external services.
//!
use crate::error::{Error, Result};
use getrandom;

/// Fill the buffer with random bytes
/// Currently implemented using `getrandom` crate, which uses
/// native OS/platform implementations.
pub fn fill_buf(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buf)?;
    Ok(())
}

#[cfg(test)]
mod test {

    use super::fill_buf;

    #[test]
    fn test_rand() {
        // works with zero-len buf - edge case
        let mut buf: [u8; 0] = [];
        assert! {fill_buf(&mut buf).is_ok()};

        // common key size
        let mut buf = [0u8; 32];
        assert! {fill_buf(&mut buf).is_ok()};

        let mut sum: u32 = 0;
        for val in buf.iter() {
            sum += *val as u32;
        }
        assert_ne!(sum, 0, "output not all zeroes");
    }
}
