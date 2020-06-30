//! compression using lz_fear pure rust implementation
//!

use crate::error::Result;
use bytes::{buf::BufMutExt, Buf, Bytes, BytesMut};
use lz_fear::raw; //framed::{CompressionSettings, LZ4FrameReader};
use std::io::{self, Error as IOError, ErrorKind, Write};
use std::marker::Unpin;

#[derive(Debug)]
pub struct Compressor {}

impl Compressor {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
struct CompWriter<'w> {
    out: &'w mut BytesMut,
}

impl<'comp: 'req, 'req> Compressor {
    pub async fn from_file(&self, fname: &str, writer: &mut BytesMut) -> Result<(), io::Error> {
        let v: Vec<u8> = tokio::fs::read(fname).await?;
        let b: Bytes = Bytes::from(v);
        self.from_buf(&b, writer)
    }

    /// Compress the Buf data
    /// Pass in a writer, ideally preallocated to the expected size of compressed output.
    pub fn from_buf<R>(&self, reader: &R, writer: &mut BytesMut) -> Result<(), io::Error>
    where
        R: Buf + Sync + Unpin,
    {
        if reader.remaining() < 1 << 16 {
            raw::compress2(
                reader.bytes(), // TODO: not correct!!
                0,
                &mut lz_fear::raw::U16Table::default(),
                writer.writer(),
            )?;
        } else {
            raw::compress2(
                reader.bytes(), // TODO: not correct!!
                0,
                &mut lz_fear::raw::U32Table::default(),
                writer.writer(),
            )?;
        }
        Ok(())
    }
}

impl<'w> Write for CompWriter<'w> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct Uncompressor {}

impl<'uc: 'req, 'req> Uncompressor {
    /// Create a new uncompressor
    pub fn new() -> Self {
        Self {}
    }

    /// Uncompress the slice.
    /// 'writer' should be a BytesMut
    pub async fn from_slice(
        &'uc self,
        reader: &[u8],
        writer: &'req mut BytesMut,
    ) -> Result<(), io::Error> {
        // before I change the api from BytesMut to mut Vec to accommodate lz4_fear,
        // I want to test to see if this works. This is inefficient but functioanlly correct.
        let mut out = Vec::with_capacity(writer.len());
        let _ = raw::decompress_raw(reader, &[], &mut out, std::usize::MAX)
            .map_err(|e| IOError::new(ErrorKind::Other, e))?;
        writer.extend_from_slice(&out);
        //        let _ = raw::decompress_raw(reader, &[], &mut writer, std::usize::MAX)
        //            .map_err(|e| IOError::new(ErrorKind::Other, e))?;
        Ok(())
    }
}
