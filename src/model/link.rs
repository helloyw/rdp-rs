extern crate native_tls;

use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, ErrorKind, Read, Write};
use self::native_tls::{TlsConnector, TlsStream, Certificate};
use model::data::{Message};

/// This a wrapper to work equals
/// for a stream and a TLS stream
pub enum Stream<S> {
    /// Raw stream that implement Read + Write
    Raw(S),
    /// TLS Stream
    Ssl(TlsStream<S>)
}

impl<S: Read + Write> Stream<S> {
    /// Read exactly the number of bytes present in buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0];
    /// s.read_exact(&mut result).unwrap();
    /// assert_eq!(result, [1, 2])
    /// ```
    pub fn read_exact(&mut self, buf: &mut[u8]) -> RdpResult<()> {
        match self {
            Stream::Raw(e) => e.read_exact(buf)?,
            Stream::Ssl(e) => e.read_exact(buf)?
        };
        Ok(())
    }

    /// Read all available buffer
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![1, 2, 3]));
    /// let mut result = [0, 0, 0, 0];
    /// s.read(&mut result).unwrap();
    /// assert_eq!(result, [1, 2, 3, 0])
    /// ```
    pub fn read(&mut self, buf: &mut[u8]) -> RdpResult<usize> {
        match self {
            Stream::Raw(e) => Ok(e.read(buf)?),
            Stream::Ssl(e) => Ok(e.read(buf)?)
        }
    }

    /// Write all buffer to the stream
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::Stream;
    /// use std::io::Cursor;
    /// let mut s = Stream::Raw(Cursor::new(vec![]));
    /// let result = [1, 2, 3, 4];
    /// s.write(&result).unwrap();
    /// if let Stream::Raw(r) = s {
    ///     assert_eq!(r.into_inner(), [1, 2, 3, 4])
    /// }
    /// else {
    ///     panic!("invalid")
    /// }
    /// ```
    pub fn write(&mut self, buffer: &[u8]) -> RdpResult<usize> {
        Ok(match self {
            Stream::Raw(e) => e.write(buffer)?,
            Stream::Ssl(e) => e.write(buffer)?
        })
    }

    /// Shutdown the stream
    /// Only works when stream is a SSL stream
    pub fn shutdown(&mut self) -> RdpResult<()> {
        Ok(match self {
            Stream::Ssl(e) => e.shutdown()?,
            _ => ()
        })
    }
}

/// Link layer is a wrapper around TCP or SSL stream
/// It can swicth from TCP to SSL
pub struct Link<S> {
    stream: Stream<S>,
    /// Bytes already pulled off the socket that do not yet form a complete
    /// frame. Keeping them here is what makes frame reading resumable: a socket
    /// read timeout can never split a frame any more.
    pending: Vec<u8>
}

impl<S: Read + Write> Link<S> {
    /// Create a new link layer from a Stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// use std::net::{TcpStream, SocketAddr};
    /// let link = Link::new(Stream::Raw(Cursor::new(vec![])));
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// ```
    pub fn new(stream: Stream<S>) -> Self {
        Link {
            stream,
            pending: Vec::new()
        }
    }

    /// This method is designed to write a Message
    /// either for TCP or SSL stream
    ///
    /// # Example
    /// ```
    /// # #[macro_use]
    /// # extern crate rdp;
    /// # use rdp::model::data::{Component, U32};
    /// # use rdp::model::link::{Link, Stream};
    /// # use std::io::Cursor;
    /// # fn main() {
    ///     let mut link = Link::new(Stream::Raw(Cursor::new(vec![])));
    ///     link.write(&component![
    ///         "foo" => U32::LE(1)
    ///     ]).unwrap();
    ///
    ///     if let Stream::Raw(r) = link.get_stream() {
    ///         assert_eq!(r.into_inner(), [1, 0, 0, 0])
    ///     }
    ///     else {
    ///         panic!("invalid")
    ///     }
    /// # }
    /// ```
    pub fn write(&mut self, message: &dyn Message) -> RdpResult<()> {
        let mut buffer = Cursor::new(Vec::new());
        message.write(&mut buffer)?;
        self.stream.write(buffer.into_inner().as_slice())?;
        Ok(())
    }

    /// This function will block until the expected size will be read
    ///
    /// # Example
    /// ```
    /// use rdp::model::link::{Link, Stream};
    /// use std::io::Cursor;
    /// let mut link = Link::new(Stream::Raw(Cursor::new(vec![0, 1, 2])));
    /// assert_eq!(link.read(2).unwrap(), [0, 1])
    /// ```
    pub fn read(&mut self, expected_size: usize) -> RdpResult<Vec<u8>> {
        if expected_size == 0 {
            let mut buffer = vec![0; 1500];
            let size = self.stream.read(&mut buffer)?;
            buffer.resize(size, 0);
            Ok(buffer)
        }
        else {
            // Only the CredSSP handshake uses this, and it runs before any
            // socket read timeout is installed, so blocking here is correct.
            let mut buffer = vec![0; expected_size];
            self.stream.read_exact(&mut buffer)?;
            Ok(buffer)
        }
    }

    /// Decide the total size of the frame sitting at the head of `pending`.
    /// `Ok(None)` means more bytes are needed before that can be known.
    fn pending_frame_size(pending: &[u8]) -> RdpResult<Option<usize>> {
        if pending.is_empty() {
            return Ok(None);
        }
        if pending[0] == 0x03 {
            // TPKT: version, reserved, then a 16 bit big endian total length.
            if pending.len() < 4 {
                return Ok(None);
            }
            let total = u16::from_be_bytes([pending[2], pending[3]]) as usize;
            if total < 4 {
                return Err(Error::RdpError(RdpError::new(
                    RdpErrorKind::InvalidSize,
                    "Invalid minimal size for TPKT",
                )));
            }
            Ok(Some(total))
        } else {
            // Fast path: the length is carried by the byte after the header.
            if pending.len() < 2 {
                return Ok(None);
            }
            let short = pending[1];
            if short & 0x80 != 0 {
                if pending.len() < 3 {
                    return Ok(None);
                }
                let total = (((short & 0x7f) as usize) << 8) | pending[2] as usize;
                if total < 3 {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidSize,
                        "Invalid minimal size for TPKT",
                    )));
                }
                Ok(Some(total))
            } else {
                if (short as usize) < 2 {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidSize,
                        "Invalid minimal size for TPKT",
                    )));
                }
                Ok(Some(short as usize))
            }
        }
    }

    fn take_pending_frame(&mut self, total: usize) -> Vec<u8> {
        let rest = self.pending.split_off(total);
        std::mem::replace(&mut self.pending, rest)
    }

    /// Assemble exactly one complete TPKT or fast path frame.
    ///
    /// Bytes that do not yet form a complete frame stay buffered and the call
    /// reports a timeout instead of blocking. That matters twice over: a socket
    /// read timeout can no longer split a frame (which used to silently drop
    /// bytes and desynchronise the whole stream) while the caller still gets
    /// control back regularly to flush queued input.
    pub fn read_frame(&mut self) -> RdpResult<Vec<u8>> {
        loop {
            if let Some(total) = Self::pending_frame_size(&self.pending)? {
                if self.pending.len() >= total {
                    return Ok(self.take_pending_frame(total));
                }
            }

            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(Error::RdpError(RdpError::new(
                        RdpErrorKind::InvalidData,
                        "stream closed while reading a frame",
                    )))
                }
                Ok(size) => self.pending.extend_from_slice(&chunk[..size]),
                Err(Error::Io(ref e))
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                {
                    if let Some(total) = Self::pending_frame_size(&self.pending)? {
                        if self.pending.len() >= total {
                            return Ok(self.take_pending_frame(total));
                        }
                    }
                    let kind = e.kind();
                    return Err(Error::Io(std::io::Error::new(
                        kind,
                        "incomplete frame, received bytes are kept buffered",
                    )));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Start a ssl connection from a raw stream
    ///
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// ```
    pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Link<S>> {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(!check_certificate);
        builder.use_sni(false);

        let connector = builder.build()?;

        if let Stream::Raw(stream) = self.stream {
            return Ok(Link::new(Stream::Ssl(connector.connect("", stream)?)))
        }
        Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, "start_ssl on ssl stream is forbidden")))
    }

    /// Retrive the peer certificate
    /// Use by the NLA authentication protocol
    /// to avoid MITM attack
    /// # Example
    /// ```no_run
    /// use rdp::model::link::{Link, Stream};
    /// use std::net::{TcpStream, SocketAddr};
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let link_tcp = Link::new(Stream::Raw(TcpStream::connect(&addr).unwrap()));
    /// let link_ssl = link_tcp.start_ssl(false).unwrap();
    /// let certificate = link_ssl.get_peer_certificate().unwrap().unwrap();
    /// ```
    pub fn get_peer_certificate(&self) -> RdpResult<Option<Certificate>> {
        if let Stream::Ssl(stream) = &self.stream {
            Ok(stream.peer_certificate()?)
        }
        else {
            Err(Error::RdpError(RdpError::new(RdpErrorKind::InvalidData, "get peer certificate on non ssl link is impossible")))
        }
    }

    /// Close the stream
    /// Only works on SSL Stream
    pub fn shutdown(&mut self) -> RdpResult<()> {
        self.stream.shutdown()
    }

    #[cfg(feature = "integration")]
    pub fn get_stream(self) -> Stream<S> {
        self.stream
    }
}
