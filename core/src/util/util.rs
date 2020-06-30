// src/util.rs

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};

/// Create a vector of specific size with uninitialized data.
/// This should only be used if the vector will be
/// immediately filled from a subsequent operation.
/// ```
/// use secret_keeper::util::uninitialized_vec;
/// assert_eq!(uninitialized_vec(3).len(), 3);
/// ```
#[inline]
pub fn uninitialized_vec(sz: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(sz);
    unsafe {
        // from std::vec::Vec (v1.42.0): "using unsafe code to write
        // to the excess capacity, and then increasing the length to match,
        // is always valid"
        v.set_len(sz);
    }
    v
}

/// Create a vector of specific size with uninitialized data.
/// This should only be used if the vector will be
/// immediately filled from a subsequent operation.
/// ```
/// use secret_keeper::util::uninitialized_bytes;
/// assert_eq!(uninitialized_bytes(3).len(), 3);
/// ```
#[inline]
#[inline]
pub fn uninitialized_bytes(sz: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(sz);
    unsafe {
        // from std::vec::Vec (v1.42.0): "using unsafe code to write
        // to the excess capacity, and then increasing the length to match,
        // is always valid"
        buf.set_len(sz);
    }
    buf
}

/// retrieve environment variable
pub fn getenv(key: &str) -> Result<String, Error> {
    std::env::var(key).map_err(|_| Error::OtherError(format!("Undefined environment var: {}", key)))
}

/// retrieve environment variable, with default vaule
pub fn getenv_default(key: &str, default_val: &str) -> String {
    match std::env::var(key) {
        Ok(v) => v,
        Err(_) => String::from(default_val),
    }
}

/// copies from reader to writer. Differs from std::io::copy in the following ways:
/// - asynchronous, with traits Buf & BufMut that support AsyncRead,AsyncWrite
/// - reader parameter is not mut !
/// - doesn't use unsafe internally
/// - doesn't use intermediate buffer
/// Returns number of bytes written
pub async fn copy_buf<R, W>(reader: &R, writer: &mut W) -> u64
where
    R: Buf,
    W: BufMut,
{
    let mut written: usize = 0;
    while reader.remaining() > written {
        let src = reader.bytes();
        writer.put_slice(src);
        written += src.len();
    }
    written as u64
}

/// parse the list of key-value tuples to find the value associated with the given key.
/// This is useful for parsing the results of `serde_urlencoded::from_str`.
///
/// ```
///   use secret_keeper::util::form_get;
///   let fields = vec!{ ("one".to_string(),"apple".to_string()),
///                      ("two".to_string(),"banana".to_string()) };
///   assert_eq!(form_get(&fields, "one"), Some("apple"));
///   assert_eq!(form_get(&fields, "two"), Some("banana"));
///   assert_eq!(form_get(&fields, "three"), None);
/// ```
pub fn form_get<'v>(fields: &'v Vec<(String, String)>, key: &str) -> Option<&'v str> {
    fields.iter().find(|v| v.0 == key).map(|v| v.1.as_str())
}

#[cfg(test)]
mod test {

    use super::*;
    use bytes::Bytes;
    use secret_keeper_test_util::{arrays_eq, random_bytes};

    #[test]
    fn gen_random() {
        let len = 20;

        // ensure generated array is correct length
        let b = random_bytes(len);
        assert_eq!(b.len(), len);

        // ensure it doesn't generate all zeroes
        let nonzero: Bytes = b.into_iter().filter(|x: &u8| *x != 0).collect();
        assert!(nonzero.len() > 0);
    }

    #[tokio::test]
    async fn copy_short() {
        const SRC_SIZE: usize = 10;
        // dest bigger than src
        let src = vec![1u8; SRC_SIZE];
        let srcb = Bytes::from(src);
        let mut dest = BytesMut::with_capacity(100);
        let n = copy_buf(&srcb, &mut dest).await;
        assert_eq!(SRC_SIZE as u64, n);

        assert!(arrays_eq(&srcb, &dest));
    }

    #[tokio::test]
    async fn copy_long() {
        const SRC_SIZE: usize = 1000;
        let src = vec![2u8; SRC_SIZE];
        let srcb = Bytes::from(src);
        let mut dest = BytesMut::with_capacity(5);
        let n = copy_buf(&srcb, &mut dest).await;
        assert_eq!(SRC_SIZE as u64, n);
        assert_eq!(dest.len() as u64, n);
        assert!(arrays_eq(&srcb, &dest));
    }
}
