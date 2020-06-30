//! test utilities

use bytes::BytesMut;
use random_fast_rng::{FastRng, Random};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// compare two arrays for equality
/// Returns true if arrays have the same length and corresponding elements are "equal"
/// ```
/// use secret_keeper_test_util::arrays_eq;
/// let first: Vec<u8> = vec![1,2,3,4,5];
/// let mut second: Vec<u8> = Vec::new();
/// second.extend_from_slice(&first);
/// assert!(arrays_eq(&first, &second));
/// ```
pub fn arrays_eq<T: PartialEq>(a1: &[T], a2: &[T]) -> bool {
    a1.len() == a2.len() && a1.iter().zip(a2.iter()).all(|(a, b)| a == b)
}

/// Create a BytesMut buffer and fill with random data.
/// This does not generate cryptographically secure RNGs. Do NOT use this to generate keys,
/// except for unit tests.
/// ```
/// use secret_keeper_test_util::random_bytes;
/// const BUF_LEN:usize = 128;
/// let data = random_bytes(BUF_LEN);
/// assert!(data.len() == BUF_LEN);
/// ```
pub fn random_bytes(len: usize) -> BytesMut {
    let mut buf = uninitialized_bytes(len);
    FastRng::new().fill_bytes(buf.as_mut());
    buf
}

/// Fill buffer with random (English) word-like text
/// ```
/// use secret_keeper_test_util::{random_fill_text, uninitialized_bytes};
/// use random_fast_rng::FastRng;
/// const BUF_LEN:usize = 256;
/// let mut rng = FastRng::new();
/// let mut buf = uninitialized_bytes(BUF_LEN);
/// random_fill_text(&mut rng, &mut buf);
/// ```
pub fn random_fill_text(rng: &mut FastRng, buf: &mut [u8]) {
    // this string must be 32 chars (or longer) for bitmask below to work
    const ENGLISH_TEXT_CHARS: &[u8] = b"abcdefghijklmnoprstuvwxyz   etao";
    // First, fill buffer with random bytes
    // Then replace bytes with ascii letters & spaces
    // FastRng::new().fill_bytes(&mut buf[..]);
    for i in 0..buf.len() {
        buf[i] = ENGLISH_TEXT_CHARS[rng.get_u8() as usize & 31]
    }
}

pub enum TestDataKind {
    Binary,
    PseudoText,
}

/// Creates file with random data. Returns temp file.
/// ```
/// use secret_keeper_test_util::{create_test_file, TestDataKind::Binary};
/// use tokio::fs::File;
/// # use tokio_test;
/// # tokio_test::block_on( async {
/// const FSIZE:usize = 1024;
/// let f = create_test_file(FSIZE, Binary).await.expect("create");
/// let flen = File::open(f.as_path()).await.expect("open")
///                  .metadata().await.expect("metadata")
///                  .len();
/// assert_eq!(FSIZE, flen as usize);
/// # });
/// ```
pub async fn create_test_file(
    len: usize,
    contents: TestDataKind,
) -> Result<mktemp::Temp, std::io::Error> {
    const BUF_LEN: usize = 8192;
    let mut rng = FastRng::new();

    let tmpfile = mktemp::Temp::new_path();
    let mut test_out = File::create(&tmpfile).await?;
    let mut copy_buf = uninitialized_bytes(BUF_LEN);
    let mut written: usize = 0;

    while written < len {
        let count: usize = std::cmp::min(BUF_LEN, len - written);
        match &contents {
            TestDataKind::Binary => rng.fill_bytes(&mut copy_buf[..count]),
            TestDataKind::PseudoText => random_fill_text(&mut rng, &mut copy_buf[..count]),
        }
        let _ = test_out.write_all(&copy_buf[..count]).await?;
        written += count;
    }
    test_out.sync_all().await?;
    Ok(tmpfile)
}

/// Create a vector of specific size with uninitialized data.
/// This should only be used if the vector will be
/// immediately filled from a subsequent operation.
/// ```
/// use secret_keeper_test_util::uninitialized_bytes;
/// assert_eq!(uninitialized_bytes(3).len(), 3);
/// ```
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

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use random_fast_rng::FastRng;

    #[test]
    fn gen_random() {
        let len: usize = 20;
        // ensure generated array is correct length
        let b = random_bytes(len);
        assert_eq!(b.len(), len);

        // ensure it doesn't generate all zeroes
        let nonzero: Bytes = b.into_iter().filter(|x: &u8| *x != 0).collect();
        assert!(nonzero.len() > 0);
    }

    #[test]
    fn random_words() {
        const BUF_LEN: usize = 256;
        let mut rng = FastRng::new();
        let mut buf = uninitialized_bytes(BUF_LEN);
        random_fill_text(&mut rng, &mut buf);
        let text = String::from_utf8(buf.to_vec()).expect("utf8");
        let words: Vec<&str> = text.split(|c| c == ' ').collect();
        eprintln!("words: [#{}] {:?}", words.len(), &words);
        assert!(words.len() > 4);
    }
}
