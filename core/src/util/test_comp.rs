#[cfg(test)]
mod test {

    use super::super::*;
    use bytes::{Buf, BytesMut};
    use secret_keeper_test_util::random_bytes;
    use std::io;

    const TEST_BUF_LEN: usize = 500;

    #[tokio::test]
    async fn compress_uncompress() -> Result<(), io::Error> {
        let comp_in = random_bytes(TEST_BUF_LEN);
        let data_len = comp_in.len();

        let mut comp_dest = BytesMut::new();

        let _ = Compressor::new().from_buf(&comp_in, &mut comp_dest)?;

        // use small capacity to force  multiple reads
        let uc = Uncompressor::new();
        let compressed_size = comp_dest.len();

        // use small initial capacity to test auto-grow
        let mut decomp = BytesMut::with_capacity(5);
        let _ = uc.from_slice(&comp_dest.freeze(), &mut decomp).await?;

        assert_eq!(
            &comp_in,
            decomp.freeze().bytes(),
            "{}",
            "data same after decomp",
        );

        println!(
            "compress ratio: {}",
            1.0 - (100.0 * compressed_size as f64) / (data_len as f64)
        );
        Ok(())
    }
}
