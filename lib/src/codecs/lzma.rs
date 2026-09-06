use lzma_rust2::{Action, LzmaOptions, LzmaStream, LzmaWriter, Status};

use super::Coder;
use crate::io;

enum Inner<W: io::Write> {
    Encoder(Box<LzmaWriter<W>>),
    Decoder { w: W, stream: Box<LzmaStream> },
}

pub struct Writer<W: io::Write> {
    inner: Inner<W>,
}

impl<W: io::Write> Writer<W> {
    pub fn decompressor(w: W) -> Result<Self, io::Error> {
        let stream = LzmaStream::new_mem_limit(u32::MAX, None);
        Ok(Self { inner: Inner::Decoder { w, stream: Box::new(stream) } })
    }

    pub fn compressor(w: W, preset: u32) -> Result<Self, io::Error> {
        let options = LzmaOptions::with_preset(preset);
        let enc = LzmaWriter::new_use_header(w, &options, None).map_err(io::Error::other)?;
        Ok(Self { inner: Inner::Encoder(Box::new(enc)) })
    }
}

impl<W: io::Write> Coder<W> for Writer<W> {
    fn get_mut(&mut self) -> &mut W {
        match &mut self.inner {
            Inner::Encoder(w) => w.inner_mut(),
            Inner::Decoder { w, .. } => w,
        }
    }

    fn finish(self) -> io::Result<W> {
        match self.inner {
            Inner::Encoder(w) => w.finish().map_err(io::Error::other),
            Inner::Decoder { mut w, mut stream } => {
                let mut buffer = [0u8; io::BUFFER_SIZE];
                loop {
                    let res = stream
                        .process(&[], &mut buffer, Action::Finish)
                        .map_err(io::Error::other)?;
                    w.write_all(&buffer[..res.bytes_produced])?;
                    if res.status == Status::StreamEnd {
                        return Ok(w);
                    }
                }
            }
        }
    }

    fn finish_boxed(self: Box<Self>) -> io::Result<W> {
        (*self).finish()
    }
}

impl<W: io::Write> io::Write for Writer<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Encoder(w) => w.write(input),
            Inner::Decoder { w, stream } => {
                let mut buffer = [0u8; io::BUFFER_SIZE];
                let total_in = input.len();
                while !input.is_empty() {
                    let res = stream
                        .process(input, &mut buffer, Action::Run)
                        .map_err(io::Error::other)?;
                    input = &input[res.bytes_consumed..];
                    w.write_all(&buffer[..res.bytes_produced])?;
                    if res.status == Status::StreamEnd {
                        break;
                    }
                }
                Ok(total_in)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Inner::Encoder(w) => w.flush(),
            Inner::Decoder { w, .. } => w.flush(),
        }
    }
}
