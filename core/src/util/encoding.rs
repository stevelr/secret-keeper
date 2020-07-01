use crate::error::{Error, Result};
use bech32::{self, FromBase32, ToBase32};
use bytes::Bytes;
use std::fmt;

/// All secret-keeper wrapped keys begin with this prefix
const KEY_PREFIX: &str = "sk";

/// Types convertible to bech32-encoded string
pub trait ToBech32 {
    fn to_bech32(&self) -> String;

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// Bech32-encoded String that can be decoded into Vector
pub trait FromBech32 {
    fn from_bech32(&self) -> Result<Vec<u8>, Error>;
}

impl ToBech32 for Vec<u8> {
    fn to_bech32(&self) -> String {
        bech32::encode(KEY_PREFIX, &self.as_slice().to_base32()).unwrap()
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

impl ToBech32 for Bytes {
    fn to_bech32(&self) -> String {
        bech32::encode(KEY_PREFIX, &self.to_base32()).unwrap()
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

impl ToBech32 for &[u8] {
    fn to_bech32(&self) -> String {
        bech32::encode(KEY_PREFIX, &self.to_base32()).unwrap()
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

impl FromBech32 for &String {
    fn from_bech32(&self) -> Result<Vec<u8>, Error> {
        let (hrp, data) = bech32::decode(self).map_err(|e| Error::KeyEncodingError(e))?;
        assert_eq!(hrp, KEY_PREFIX);
        let v = Vec::<u8>::from_base32(&data).map_err(|e| Error::KeyEncodingError(e))?;
        Ok(v)
    }
}

impl FromBech32 for String {
    fn from_bech32(&self) -> Result<Vec<u8>, Error> {
        let (hrp, data) = bech32::decode(self).map_err(|e| Error::KeyEncodingError(e))?;
        assert_eq!(hrp, KEY_PREFIX);
        let v = Vec::<u8>::from_base32(&data).map_err(|e| Error::KeyEncodingError(e))?;
        Ok(v)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use secret_keeper_test_util::{arrays_eq, random_bytes};

    #[test]
    fn bech32_tofrom() -> Result<(), Error> {
        let buf = random_bytes(32);

        let enc_buf: String = buf.as_ref().to_bech32();
        println!("orig       : {}", hex::encode(&buf));
        println!("orig-bech32: {}", hex::encode(String::from(&enc_buf)));

        let key = (&enc_buf).from_bech32()?;
        println!("key bin:     {}", hex::encode(key.as_slice()));

        assert!(arrays_eq(&buf, key.as_slice()));
        Ok(())
    }
}
