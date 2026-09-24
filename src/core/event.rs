use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use num_enum::TryFromPrimitive;
use codec::rle::{rle_32_decompress, rle_16_decompress, rgb565torgb32};

/// A bitmap event is used
/// to notify client that it received
/// an old school bitmap data
///
/// If bitmap is compress you can use the
/// decompress function to handle it
#[derive(Clone)]
pub struct BitmapEvent {
    /// Pixel position from left of the left top angle
    pub dest_left: u16,
    /// Pixel position from top of the left top angle
    pub dest_top: u16,
    /// Pixel position from Right of the left top angle
    pub dest_right: u16,
    /// Pixel position from Bottom of the left top angle
    pub dest_bottom: u16,
    /// width of the bitmap buffer once decompress
    /// This can be larger than dest_right minus dest_left
    pub width: u16,
    /// height of the bitmap buffer once decompress
    /// This can be larger than dest_bottom minus dest_top
    pub height: u16,
    /// Bits Per Pixel
    pub bpp: u16,
    /// true if bitmap buffer is compressed using RLE
    pub is_compress: bool,
    /// Bitmap data
    pub data: Vec<u8>
}

impl BitmapEvent {
    /// Decompress a bitmap which has been encoded by the RLE algorithm
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::client::Connector;
    /// use rdp::core::event::RdpEvent;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let tcp = TcpStream::connect(&addr).unwrap();
    /// let mut connector = Connector::new()
    ///     .screen(800, 600)
    ///     .credentials("domain".to_string(), "username".to_string(), "password".to_string());
    /// let mut client = connector.connect(tcp).unwrap();
    /// client.read(|rdp_event| {
    ///     match rdp_event {
    ///         RdpEvent::Bitmap(bitmap) => {
    ///             let data = if bitmap.is_compress {
    ///                 bitmap.decompress().unwrap()
    ///             }
    ///             else {
    ///                 bitmap.data
    ///             };
    ///         }
    ///          _ => println!("Unhandled event")
    ///     }
    /// }).unwrap()
    /// ```
    pub fn decompress(self) -> RdpResult<Vec<u8>> {

        // actually only handle 32 bpp
        match self.bpp {
            32 => {
                // 32 bpp is straight forward
                Ok(
                    if self.is_compress {
                        let mut result = vec![0 as u8; self.width as usize * self.height as usize * 4];
                        rle_32_decompress(&self.data, self.width as u32, self.height as u32, &mut result)?;
                        result
                    } else {
                        self.data
                    }
                )
            },
            16 => {
                // 16 bpp is more consumer
                let result_16bpp = if self.is_compress {
                    let mut result = vec![0 as u16; self.width as usize * self.height as usize * 2];
                    rle_16_decompress(&self.data, self.width as usize, self.height as usize, &mut result)?;
                    result
                } else {
                    let mut result = vec![0 as u16; self.width as usize * self.height as usize];
                    for i in 0..self.height {
                        for j in 0..self.width {
                            let src = (((self.height - i - 1) * self.width + j) * 2) as usize;
                            result[(i * self.width + j) as usize] = (self.data[src + 1] as u16) << 8 | self.data[src] as u16;
                        }
                    }
                    result
                };

                Ok(rgb565torgb32(&result_16bpp, self.width as usize, self.height as usize))
            },
            _ => Err(Error::RdpError(RdpError::new(RdpErrorKind::NotImplemented, &format!("Decompression Algorithm not implemented for bpp {}", self.bpp))))
        }
    }
}

#[repr(u8)]
#[derive(Eq, PartialEq, TryFromPrimitive, Copy, Clone)]
pub enum PointerButton {
    /// No button but a move
    None = 0,
    /// Left mouse Button
    Left = 1,
    /// Right mouse button
    Right = 2,
    /// Wheel mouse button
    Middle = 3
}

/// A mouse pointer event
#[derive(Clone)]
pub struct PointerEvent {
    /// horizontal position from top left angle of the window
    pub x: u16,
    /// vertical position from top left angle of the window
    pub y: u16,
    /// Which button is pressed
    pub button: PointerButton,
    /// true if it's a down press action
    pub down: bool
}

/// Keyboard event
/// It's a raw event using Scancode
/// to inform which key is pressed
#[derive(Clone)]
pub struct KeyboardEvent {
    /// Scancode of the key
    pub code: u16,
    /// State of the key
    pub down: bool,
    /// True for extended keys (E0-prefixed scancodes: arrows, right Ctrl/Alt,
    /// Insert/Delete/Home/End/PageUp/PageDown). Sent as KBD_FLAGS_EXTENDED.
    pub extended: bool
}

/// A pointer shape received from the server (Color or New Pointer update).
/// The AND mask is normalized to one byte per pixel (0 or 1) so consumers
/// do not have to care about the 16/32-bit row padding rules.
#[derive(Clone)]
pub struct PointerShapeEvent {
    /// Cache slot the server will refer to with a Cached Pointer update
    pub cache_index: u16,
    /// Hot spot (the pixel of the shape that sits on the pointer position)
    pub hot_x: u16,
    pub hot_y: u16,
    pub width: u16,
    pub height: u16,
    /// Bits per pixel of the XOR mask (16, 24 or 32)
    pub bpp: u16,
    /// AND mask, one byte per pixel, row major
    pub and_mask: Vec<u8>,
    /// XOR mask, raw pixel data in `bpp` format, row major
    pub xor_mask: Vec<u8>
}

/// All event handle by RDP protocol implemented by rdp-rs
#[derive(Clone)]
pub enum RdpEvent {
    /// Classic bitmap event
    Bitmap(BitmapEvent),
    /// Mouse event
    Pointer(PointerEvent),
    /// Keyboard event
    Key(KeyboardEvent),
    /// The remote pointer moved to this position
    PointerPosition {
        x: u16,
        y: u16
    },
    /// A new pointer shape is available, cache it under `cache_index`
    PointerShape(PointerShapeEvent),
    /// Switch the visible pointer to a previously cached shape
    PointerCached(u16),
    /// Switch back to the server default (arrow) pointer
    PointerDefault,
    /// Hide the remote pointer
    PointerHidden
}