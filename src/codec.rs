#![forbid(unsafe_code)]
//! JSON-lines frame reader/writer for the lock-UI socket.
//!
//! Identical contract to lion-greeter's codec: a frame (line) larger than
//! [`MAX_LINE_BYTES`] aborts the connection; frames must be valid UTF-8;
//! bytes handed to the caller are owned by a `Zeroizing<String>` so
//! password material in `Answer` lines is wiped on drop (spec 03 §8).

use crate::error::{Error, Result};
use crate::proto::MAX_LINE_BYTES;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub struct FrameReader<R> {
    inner: Pin<Box<R>>,
    buf: Vec<u8>,
    eof: bool,
}

impl<R: AsyncRead> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner: Box::pin(inner),
            buf: Vec::with_capacity(512),
            eof: false,
        }
    }

    /// Next frame as a zeroizing string, or `None` on clean EOF.
    pub async fn next_frame(&mut self) -> Result<Option<Zeroizing<String>>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                match String::from_utf8(line) {
                    Ok(s) => return Ok(Some(Zeroizing::new(s))),
                    Err(e) => {
                        let mut bad = e.into_bytes();
                        wipe(&mut bad);
                        return Err(Error::Protocol("frame is not valid UTF-8".into()));
                    }
                }
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let mut bad = std::mem::take(&mut self.buf);
                wipe(&mut bad);
                return Err(Error::Protocol("trailing partial frame at EOF".into()));
            }
            if self.buf.len() >= MAX_LINE_BYTES {
                let mut bad = std::mem::take(&mut self.buf);
                wipe(&mut bad);
                return Err(Error::Protocol(format!(
                    "frame exceeds {MAX_LINE_BYTES} bytes; connection dropped"
                )));
            }
            let mut chunk = [0u8; 2048];
            let n = self.inner.as_mut().read(&mut chunk).await?;
            if n == 0 {
                self.eof = true;
            } else {
                self.buf.extend_from_slice(&chunk[..n]);
            }
            // Wipe the stack chunk too: it may have carried secret bytes.
            wipe_slice(&mut chunk);
        }
    }
}

/// Writes single frames. The writer side never emits secret material.
pub struct FrameWriter<W> {
    inner: Pin<Box<W>>,
}

impl<W: AsyncWrite> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        FrameWriter {
            inner: Box::pin(inner),
        }
    }

    pub async fn write_frame(&mut self, line: &str) -> Result<()> {
        let mut out = Vec::with_capacity(line.len() + 1);
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
        self.inner.as_mut().write_all(&out).await?;
        Ok(self.inner.as_mut().flush().await?)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        Ok(self.inner.as_mut().shutdown().await?)
    }
}

fn wipe(v: &mut Vec<u8>) {
    use zeroize::Zeroize;
    v.zeroize();
    v.clear();
}

fn wipe_slice(s: &mut [u8]) {
    use zeroize::Zeroize;
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn splits_lines_and_ignores_blanks() {
        let (mut w, r) = tokio::io::duplex(64);
        w.write_all(b"  \n{\"a\":1}\r\n{\"a\":2}\n").await.unwrap();
        drop(w);
        let mut fr = FrameReader::new(r);
        assert_eq!(&*fr.next_frame().await.unwrap().unwrap(), r#"{"a":1}"#);
        assert_eq!(&*fr.next_frame().await.unwrap().unwrap(), r#"{"a":2}"#);
        assert!(fr.next_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_frame_errors() {
        let (mut w, r) = tokio::io::duplex(64 * 1024);
        let big = vec![b'x'; MAX_LINE_BYTES + 100];
        tokio::spawn(async move {
            let _ = w.write_all(&big).await;
        });
        let mut fr = FrameReader::new(r);
        assert!(matches!(fr.next_frame().await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn invalid_utf8_errors() {
        let (mut w, r) = tokio::io::duplex(64);
        w.write_all(&[0xff, 0xfe, b'\n']).await.unwrap();
        drop(w);
        let mut fr = FrameReader::new(r);
        assert!(matches!(fr.next_frame().await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn partial_frame_at_eof_errors() {
        let (mut w, r) = tokio::io::duplex(64);
        w.write_all(b"{\"a\":").await.unwrap();
        drop(w);
        let mut fr = FrameReader::new(r);
        assert!(matches!(fr.next_frame().await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn writer_appends_lf() {
        let (w, mut r) = tokio::io::duplex(64);
        let mut fw = FrameWriter::new(w);
        fw.write_frame("hi").await.unwrap();
        fw.shutdown().await.unwrap();
        let mut s = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut r, &mut s)
            .await
            .unwrap();
        assert_eq!(s, "hi\n");
    }
}
