use core::mcs;
use core::tpkt;
use core::event::{ClipboardEvent, ClipboardFormat, FileContentsRequest, RdpEvent};
use model::error::{RdpResult, Error, RdpError, RdpErrorKind};
use std::io::{Cursor, Read, Write};

/// CLIPRDR message types (MS-RDPECLIP 2.2.1)
const CB_MONITOR_READY: u16 = 0x0001;
const CB_FORMAT_LIST: u16 = 0x0002;
const CB_FORMAT_LIST_RESPONSE: u16 = 0x0003;
const CB_FORMAT_DATA_REQUEST: u16 = 0x0004;
const CB_FORMAT_DATA_RESPONSE: u16 = 0x0005;
const CB_CLIP_CAPS: u16 = 0x0007;
const CB_FILECONTENTS_REQUEST: u16 = 0x0008;
const CB_FILECONTENTS_RESPONSE: u16 = 0x0009;
const CB_LOCK_CLIPDATA: u16 = 0x000A;
const CB_UNLOCK_CLIPDATA: u16 = 0x000B;

const CB_RESPONSE_OK: u16 = 0x0001;
const CB_RESPONSE_FAIL: u16 = 0x0002;

/// Capability flags (MS-RDPECLIP 2.2.2.1.1.1)
const CB_USE_LONG_FORMAT_NAMES: u32 = 0x00000002;
const CB_STREAM_FILECLIP_ENABLED: u32 = 0x00000004;
const CB_FILECLIP_NO_FILE_PATHS: u32 = 0x00000008;
const CB_CAN_LOCK_CLIPDATA: u32 = 0x00000010;

/// FileContentsRequest dwFlags (MS-RDPECLIP 2.2.5.2)
pub const FILECONTENTS_SIZE: u32 = 0x00000001;
pub const FILECONTENTS_RANGE: u32 = 0x00000002;

/// Standard clipboard formats
pub const CF_TEXT: u32 = 1;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_UNICODETEXT: u32 = 13;

/// Registered format ids chosen by this client for its own announcements.
/// The ids the server uses for its own formats are learned from its
/// CB_FORMAT_LIST.
pub const CB_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W: u32 = 0xC0F0;
pub const CB_FORMAT_ID_FILE_CONTENTS: u32 = 0xC0F1;
pub const CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W: &'static str = "FileGroupDescriptorW";
pub const CB_FORMAT_NAME_FILE_CONTENTS: &'static str = "FileContents";

/// Size of a FILEDESCRIPTORW fixed part (without the file name)
const FILE_DESCRIPTOR_FIXED_SIZE: usize = 592;

fn rdp_err(kind: RdpErrorKind, msg: &str) -> Error {
    Error::RdpError(RdpError::new(kind, msg))
}

/// A file entry of a FileGroupDescriptorW list
#[derive(Clone, Debug, PartialEq)]
pub struct FileDescriptor {
    /// File name (not a full path)
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
    /// Last write time as a Windows FILETIME (100ns units since 1601-01-01);
    /// 0 means "unknown"
    pub modified: u64
}

/// Pack a CLIPRDR header + payload into a channel message
fn packet(msg_type: u16, msg_flags: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(&msg_type.to_le_bytes());
    out.extend_from_slice(&msg_flags.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Read a CLIPRDR header + payload from a channel message
fn read_packet(payload: &mut dyn Read) -> RdpResult<(u16, u16, Vec<u8>)> {
    let mut header = [0u8; 8];
    payload.read_exact(&mut header)?;
    let msg_type = u16::from_le_bytes([header[0], header[1]]);
    let msg_flags = u16::from_le_bytes([header[2], header[3]]);
    let data_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if data_len > 64 * 1024 * 1024 {
        return Err(rdp_err(RdpErrorKind::InvalidSize, "CLIPRDR: data length exceeds the 64 MB sanity bound"));
    }
    let mut data = vec![0u8; data_len];
    payload.read_exact(&mut data)?;
    Ok((msg_type, msg_flags, data))
}

/// Append one format list entry.
///
/// The long-name shape is a 4 byte format id followed by a null-terminated
/// UTF-16LE name whose length is whatever the name needs - it is *not* a fixed
/// block. Standard formats carry an empty name, so their entry is just the id
/// plus the terminator. FreeRDP reads and writes exactly that shape in
/// cliprdr_common.c (it advances `(wcslen(name) + 1) * 2` bytes per entry).
/// Emitting a fixed 64 byte name block instead made the server drop the whole
/// list without even acknowledging it, so nothing could be pasted remotely.
fn write_format_entry(out: &mut Vec<u8>, id: u32, name: &str) {
    out.extend_from_slice(&id.to_le_bytes());
    // 255 units is far beyond any real clipboard format name; the bound only
    // stops a pathological name from inflating the PDU.
    for unit in name.encode_utf16().take(255) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
}

/// Parse a whole format list.
///
/// `use_long` reflects what the peer negotiated in its CB_CLIP_CAPS and picks
/// the preferred shape. The other shape is still tried as a tolerant fallback
/// because real servers do not always honour the capability flag.
fn parse_format_list(data: &[u8], use_long: bool) -> Option<Vec<ClipboardFormat>> {
    let long_strict = || parse_long_format_list(data, true);
    let long_lenient = || parse_long_format_list(data, false);
    let short_strict = || parse_short_format_list(data, true);
    let short_lenient = || parse_short_format_list(data, false);
    if use_long {
        long_strict()
            .or_else(long_lenient)
            .or_else(short_strict)
            .or_else(short_lenient)
    } else {
        short_strict()
            .or_else(short_lenient)
            .or_else(long_strict)
            .or_else(long_lenient)
    }
}

/// Long format names: a 4 byte id followed by a null-terminated UTF-16LE name
/// of variable length.
fn parse_long_format_list(data: &[u8], strict: bool) -> Option<Vec<ClipboardFormat>> {
    if data.is_empty() {
        return None;
    }
    let mut formats = Vec::new();
    let mut pos = 0usize;
    while data.len() >= pos + 4 {
        let id = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let mut units: Vec<u16> = Vec::new();
        let mut terminated = false;
        while data.len() >= pos + 2 {
            let unit = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            if unit == 0 {
                terminated = true;
                break;
            }
            units.push(unit);
        }
        if !terminated {
            return None;
        }
        let name = String::from_utf16_lossy(&units);
        // Standard formats (id < 0xC000) carry an empty name, registered
        // formats (id >= 0xC000) a non-empty one
        if strict && (id < 0xC000) != name.is_empty() {
            return None;
        }
        formats.push(ClipboardFormat { id, name });
    }
    // Up to three trailing bytes are tolerated; a longer tail means the walk
    // lost the framing and this is not really a long-name list.
    if data.len() - pos >= 4 {
        return None;
    }
    if formats.is_empty() {
        None
    } else {
        Some(formats)
    }
}

/// Short format names: fixed 36 byte entries (4 byte id + 32 byte name block)
fn parse_short_format_list(data: &[u8], strict: bool) -> Option<Vec<ClipboardFormat>> {
    let entry_size = 4 + 32;
    if data.is_empty() || data.len() % entry_size != 0 {
        return None;
    }
    let mut formats = Vec::new();
    for chunk in data.chunks(entry_size) {
        let id = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let units: Vec<u16> = chunk[4..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let name = read_null_terminated_utf16(&units);
        if strict && (id < 0xC000) != name.is_empty() {
            return None;
        }
        formats.push(ClipboardFormat { id, name });
    }
    Some(formats)
}

fn read_null_terminated_utf16(units: &[u16]) -> String {
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Parse a FileGroupDescriptorW payload into file entries
///
/// FILEDESCRIPTORW layout (MS-RDPECLIP 2.2.5.2.2.3):
/// dwFlags(4) clsid(16) sizel(8) pointl(8) dwFileAttributes(4)
/// ftCreationTime(8) ftLastAccessTime(8) ftLastWriteTime(8)
/// nFileSizeHigh(4) nFileSizeLow(4) cFileName[260] (520 bytes UTF-16)
pub fn parse_file_group_descriptor(data: &[u8]) -> RdpResult<Vec<FileDescriptor>> {
    if data.len() < 4 {
        return Err(rdp_err(RdpErrorKind::InvalidSize, "CLIPRDR: FileGroupDescriptorW too short"));
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut files = Vec::new();
    let mut offset = 4;
    for _ in 0..count {
        if offset + FILE_DESCRIPTOR_FIXED_SIZE > data.len() {
            return Err(rdp_err(RdpErrorKind::InvalidSize, "CLIPRDR: truncated FILEDESCRIPTORW"));
        }
        let fixed = &data[offset..offset + FILE_DESCRIPTOR_FIXED_SIZE];
        let attributes = u32::from_le_bytes([fixed[36], fixed[37], fixed[38], fixed[39]]);
        let size = u32::from_le_bytes([fixed[68], fixed[69], fixed[70], fixed[71]]) as u64
            | ((u32::from_le_bytes([fixed[64], fixed[65], fixed[66], fixed[67]]) as u64) << 32);
        let units: Vec<u16> = fixed[72..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let name = read_null_terminated_utf16(&units);
        if name.is_empty() {
            return Err(rdp_err(RdpErrorKind::InvalidData, "CLIPRDR: FILEDESCRIPTORW with empty name"));
        }
        files.push(FileDescriptor {
            name,
            size,
            is_directory: attributes & 0x10 != 0,
            modified: u64::from_le_bytes([
                fixed[56], fixed[57], fixed[58], fixed[59],
                fixed[60], fixed[61], fixed[62], fixed[63]
            ])
        });
        offset += FILE_DESCRIPTOR_FIXED_SIZE;
    }
    Ok(files)
}

/// FILETIME epoch difference (1601 → 1970) in 100ns units
const FILETIME_EPOCH_OFFSET: u64 = 116444736000000000;

/// Convert a Unix timestamp to a Windows FILETIME
pub fn unix_time_to_filetime(secs: u64, nanos: u64) -> u64 {
    secs * 10_000_000 + nanos / 100 + FILETIME_EPOCH_OFFSET
}

/// Serialize a FileGroupDescriptorW payload from file entries
pub fn write_file_group_descriptor(files: &[FileDescriptor]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + files.len() * FILE_DESCRIPTOR_FIXED_SIZE);
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    // FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME | FD_PROGRESSUI | FD_UNICODE,
    // mirroring FreeRDP (winpr clipboard/synthetic_file.c). FD_ATTRIBUTES is
    // not optional in practice: without it Explorer reads the attributes as
    // zero and never proceeds to the FileContents requests.
    const FD_FLAGS: u32 = 0x00000004 | 0x00000040 | 0x00000020 | 0x00004000 | 0x80000000;
    for file in files {
        let mut fixed = [0u8; FILE_DESCRIPTOR_FIXED_SIZE];
        // dwFlags
        fixed[0..4].copy_from_slice(&FD_FLAGS.to_le_bytes());
        // dwFileAttributes
        let attributes: u32 = if file.is_directory { 0x10 } else { 0x80 };
        fixed[36..40].copy_from_slice(&attributes.to_le_bytes());
        // ftLastWriteTime
        fixed[56..64].copy_from_slice(&file.modified.to_le_bytes());
        // nFileSizeHigh / nFileSizeLow
        fixed[64..68].copy_from_slice(&((file.size >> 32) as u32).to_le_bytes());
        fixed[68..72].copy_from_slice(&(file.size as u32).to_le_bytes());
        // cFileName[260]
        for (i, c) in file.name.encode_utf16().take(259).enumerate() {
            fixed[72 + i * 2..74 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&fixed);
    }
    out
}

fn parse_file_contents_request(data: &[u8]) -> RdpResult<FileContentsRequest> {
    if data.len() < 24 {
        return Err(rdp_err(RdpErrorKind::InvalidSize, "CLIPRDR: FileContentsRequest too short"));
    }
    Ok(FileContentsRequest {
        stream_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        index: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        flags: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        position: u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64
            | ((u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as u64) << 32),
        size: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        clip_data_id: if data.len() >= 28 {
            u32::from_le_bytes([data[24], data[25], data[26], data[27]])
        } else {
            0
        }
    })
}

fn write_file_contents_request(request: &FileContentsRequest) -> Vec<u8> {
    // 28 bytes: the optional clipDataId is always written (FreeRDP does the
    // same; servers that don't use locks ignore it)
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(&request.stream_id.to_le_bytes());
    out.extend_from_slice(&request.index.to_le_bytes());
    out.extend_from_slice(&request.flags.to_le_bytes());
    out.extend_from_slice(&(request.position as u32).to_le_bytes());
    out.extend_from_slice(&((request.position >> 32) as u32).to_le_bytes());
    out.extend_from_slice(&request.size.to_le_bytes());
    out.extend_from_slice(&request.clip_data_id.to_le_bytes());
    out
}

/// CLIPRDR channel client
pub struct Client {
    /// Format id of the outstanding CB_FORMAT_DATA_REQUEST, so the matching
    /// response can be labeled without the server echoing it
    pending_format: Option<u32>,
    /// Whether the server negotiated CB_USE_LONG_FORMAT_NAMES in its capability
    /// set. Decides how *its* format lists are laid out; modern Windows always
    /// sets it, but the flag has to be honoured rather than assumed.
    server_long_format_names: bool
}

impl Client {
    pub fn new() -> Self {
        Client {
            pending_format: None,
            server_long_format_names: true
        }
    }

    /// Handle one CLIPRDR channel payload
    pub fn read<S: Read + Write, T>(&mut self, payload: tpkt::Payload, mcs: &mut mcs::Client<S>, mut callback: T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {
        let mut payload = try_let!(tpkt::Payload::Raw, payload)?;
        if std::env::var("RDP_CLIP_LOG").is_ok() {
            let mut raw = Vec::new();
            payload.read_to_end(&mut raw)?;
            eprintln!("[clip-rx] {} bytes: {:02x?}", raw.len(), &raw[..raw.len().min(24)]);
            payload = Cursor::new(raw);
        }
        // One channel message may batch several CLIPRDR messages
        while (payload.position() as usize) < payload.get_ref().len() {
            let (msg_type, msg_flags, data) = match read_packet(&mut payload) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("CLIPRDR: truncated message: {:?}", e);
                    break;
                }
            };
            self.dispatch(msg_type, msg_flags, &data, mcs, &mut callback)?;
        }
        Ok(())
    }

    fn dispatch<S: Read + Write, T>(&mut self, msg_type: u16, msg_flags: u16, data: &[u8], mcs: &mut mcs::Client<S>, callback: &mut T) -> RdpResult<()>
    where T: FnMut(RdpEvent) {

        match msg_type {
            CB_MONITOR_READY => {
                // Announce our capabilities, then let the application layer
                // know it should send its initial format list
                self.write_capabilities(mcs, true)?;
                callback(RdpEvent::Clipboard(ClipboardEvent::MonitorReady));
            },
            CB_CLIP_CAPS => {
                // General capability set from the server: generalFlags sits at
                // offset 12 (after cCapabilitiesSets, capabilitySetType and
                // capabilitySetLength)
                if data.len() >= 16 {
                    let general_flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                    self.server_long_format_names = general_flags & CB_USE_LONG_FORMAT_NAMES != 0;
                }
            },
            CB_FORMAT_LIST => {
                match parse_format_list(data, self.server_long_format_names) {
                    Some(formats) => {
                        callback(RdpEvent::Clipboard(ClipboardEvent::FormatList(formats)));
                        self.write_format_list_response(mcs)?;
                    },
                    None => {
                        eprintln!("CLIPRDR: unparseable format list ({} bytes)", data.len());
                        Self::send(mcs, CB_FORMAT_LIST_RESPONSE, 0, &[])?;
                    }
                }
            },
            CB_FORMAT_LIST_RESPONSE => {
                // Our own announcement was answered; nothing to do
            },
            CB_FORMAT_DATA_REQUEST => {
                if data.len() >= 4 {
                    let format_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    callback(RdpEvent::Clipboard(ClipboardEvent::DataRequest { format_id }));
                }
            },
            CB_FORMAT_DATA_RESPONSE => {
                let format_id = self.pending_format.take().unwrap_or(0);
                if msg_flags & CB_RESPONSE_OK != 0 || msg_flags == 0 {
                    callback(RdpEvent::Clipboard(ClipboardEvent::DataResponse { format_id, data: data.to_vec() }));
                } else {
                    eprintln!("CLIPRDR: data response failed (flags={:#x})", msg_flags);
                }
            },
            CB_FILECONTENTS_REQUEST => {
                let request = parse_file_contents_request(data)?;
                callback(RdpEvent::Clipboard(ClipboardEvent::FileContentsRequest(request)));
            },
            CB_FILECONTENTS_RESPONSE => {
                if msg_flags & CB_RESPONSE_FAIL != 0 {
                    eprintln!("CLIPRDR: file contents request failed (flags={:#x})", msg_flags);
                } else if data.len() >= 4 {
                    let stream_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    callback(RdpEvent::Clipboard(ClipboardEvent::FileContentsResponse {
                        stream_id,
                        data: data[4..].to_vec()
                    }));
                }
            },
            CB_LOCK_CLIPDATA | CB_UNLOCK_CLIPDATA => {
                // Lock/unlock acknowledgements; nothing to do
            },
            _ => {
                eprintln!("CLIPRDR: unhandled message type {:#x}", msg_type);
            }
        }
        Ok(())
    }

    /// Write one CLIPRDR message on the clipboard channel, tracing it under
    /// `RDP_CLIP_LOG` the same way the receive path does.
    fn send<S: Read + Write>(mcs: &mut mcs::Client<S>, msg_type: u16, msg_flags: u16, data: &[u8]) -> RdpResult<()> {
        if std::env::var("RDP_CLIP_LOG").is_ok() {
            eprintln!(
                "[clip-tx] type=0x{:04x} flags=0x{:04x} len={} data={:02x?}",
                msg_type,
                msg_flags,
                data.len(),
                &data[..data.len().min(24)]
            );
        }
        mcs.write(&"cliprdr".to_string(), packet(msg_type, msg_flags, data))
    }

    /// Send one clipboard event to the server
    pub fn write<S: Read + Write>(&mut self, event: ClipboardEvent, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        match event {
            ClipboardEvent::MonitorReady => {
                // Monitor Ready is exchanged in BOTH directions (MS-RDPECLIP
                // 2.2.1.1); Windows waits for the client's before it treats the
                // channel as usable and starts forwarding clipboard changes.
                Self::send(mcs, CB_MONITOR_READY, 0, &[])
            },
            ClipboardEvent::FormatList(formats) => {
                let mut data = Vec::new();
                for format in &formats {
                    write_format_entry(&mut data, format.id, &format.name);
                }
                Self::send(mcs, CB_FORMAT_LIST, 0, &data)
            },
            ClipboardEvent::FormatListResponse => {
                Self::send(mcs, CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[])
            },
            ClipboardEvent::DataRequest { format_id } => {
                self.pending_format = Some(format_id);
                Self::send(mcs, CB_FORMAT_DATA_REQUEST, 0, &format_id.to_le_bytes())
            },
            ClipboardEvent::DataResponse { format_id, data } => {
                // The server matches responses to requests by order, the
                // format id is not echoed on the wire
                let _ = format_id;
                Self::send(mcs, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, &data)
            },
            ClipboardEvent::FileContentsRequest(request) => {
                Self::send(mcs, CB_FILECONTENTS_REQUEST, 0, &write_file_contents_request(&request))
            },
            ClipboardEvent::FileContentsResponse { stream_id, data } => {
                let mut payload = Vec::with_capacity(4 + data.len());
                payload.extend_from_slice(&stream_id.to_le_bytes());
                payload.extend_from_slice(&data);
                Self::send(mcs, CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, &payload)
            },
            ClipboardEvent::LockClipboardData { clip_data_id } => {
                Self::send(mcs, CB_LOCK_CLIPDATA, 0, &clip_data_id.to_le_bytes())
            },
            ClipboardEvent::UnlockClipboardData { clip_data_id } => {
                Self::send(mcs, CB_UNLOCK_CLIPDATA, 0, &clip_data_id.to_le_bytes())
            }
        }
    }

    /// Announce the clipboard capability sets (long format names + file
    /// streaming), expected right after CB_MONITOR_READY
    fn write_capabilities<S: Read + Write>(&self, mcs: &mut mcs::Client<S>, file_clip: bool) -> RdpResult<()> {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&1u16.to_le_bytes()); // numCapabilitySets
        data.extend_from_slice(&0u16.to_le_bytes()); // pad
        data.extend_from_slice(&1u16.to_le_bytes()); // capabilitySetType = general
        data.extend_from_slice(&12u16.to_le_bytes()); // capabilitySetLength
        data.extend_from_slice(&2u32.to_le_bytes()); // version = CB_CAPS_VERSION_2
        // Exactly what a working client advertises for a text clipboard:
        // FreeRDP's X11 client sends CB_CAPS_VERSION_2 with only
        // CB_USE_LONG_FORMAT_NAMES set, and Windows answers its format list.
        // Advertising the file/lock flags unconditionally made the server
        // ignore every message this client sent.
        let mut flags = CB_USE_LONG_FORMAT_NAMES;
        if file_clip {
            flags |= CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS;
        }
        data.extend_from_slice(&flags.to_le_bytes());
        Self::send(mcs, CB_CLIP_CAPS, 0, &data)
    }

    fn write_format_list_response<S: Read + Write>(&self, mcs: &mut mcs::Client<S>) -> RdpResult<()> {
        Self::send(mcs, CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, &[])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    fn formats() -> Vec<ClipboardFormat> {
        vec![
            ClipboardFormat { id: CF_UNICODETEXT, name: String::new() },
            ClipboardFormat { id: CB_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W, name: CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W.to_string() },
        ]
    }

    #[test]
    fn test_format_list_roundtrip() {
        let mut data = Vec::new();
        for f in formats() {
            write_format_entry(&mut data, f.id, &f.name);
        }
        // Long names are variable length: id(4) + name + NUL, so an empty name
        // costs 6 bytes and "FileGroupDescriptorW" costs 4 + 40 + 2.
        assert_eq!(data.len(), 6 + 4 + CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W.len() * 2 + 2);
        let parsed = parse_format_list(&data, true).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, CF_UNICODETEXT);
        assert_eq!(parsed[0].name, "");
        assert_eq!(parsed[1].id, CB_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W);
        assert_eq!(parsed[1].name, CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W);
    }

    /// The exact byte shape a real server sends for a standard format plus a
    /// registered one, so the variable-length walk is pinned down.
    #[test]
    fn test_parse_long_format_list_wire_shape() {
        let mut data = Vec::new();
        data.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&CB_FORMAT_ID_FILE_GROUP_DESCRIPTOR_W.to_le_bytes());
        for unit in CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(data.len(), 6 + 46);
        let parsed = parse_format_list(&data, true).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, CF_UNICODETEXT);
        assert_eq!(parsed[1].name, CB_FORMAT_NAME_FILE_GROUP_DESCRIPTOR_W);
    }

    #[test]
    fn test_format_list_short_names() {
        // Short names: 4 + 32 bytes per entry
        let mut data = Vec::new();
        data.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        let parsed = parse_format_list(&data, false).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, CF_UNICODETEXT);
    }

    #[test]
    fn test_file_group_descriptor_roundtrip() {
        let files = vec![
            FileDescriptor { name: "hello.txt".to_string(), size: 12345, is_directory: false, modified: 133_000_000_000_000_000 },
            FileDescriptor { name: "目录".to_string(), size: 0, is_directory: true, modified: 0 },
        ];
        let data = write_file_group_descriptor(&files);
        assert_eq!(data.len(), 4 + 2 * FILE_DESCRIPTOR_FIXED_SIZE);
        let parsed = parse_file_group_descriptor(&data).unwrap();
        assert_eq!(parsed, files);
    }

    #[test]
    fn test_file_contents_request_roundtrip() {
        let request = FileContentsRequest {
            stream_id: 7,
            index: 1,
            flags: FILECONTENTS_RANGE,
            position: 0x1_0000_0000,
            size: 65536,
            clip_data_id: 42,
        };
        let data = write_file_contents_request(&request);
        assert_eq!(data.len(), 28);
        let parsed = parse_file_contents_request(&data).unwrap();
        assert_eq!(parsed.stream_id, 7);
        assert_eq!(parsed.index, 1);
        assert_eq!(parsed.clip_data_id, 42);
        assert_eq!(parsed.flags, FILECONTENTS_RANGE);
        assert_eq!(parsed.position, 0x1_0000_0000);
        assert_eq!(parsed.size, 65536);
    }

    #[test]
    fn test_packet_roundtrip() {
        let p = packet(CB_FORMAT_DATA_REQUEST, 0, &13u32.to_le_bytes());
        let (msg_type, msg_flags, data) = read_packet(&mut Cursor::new(p)).unwrap();
        assert_eq!(msg_type, CB_FORMAT_DATA_REQUEST);
        assert_eq!(msg_flags, 0);
        assert_eq!(data, 13u32.to_le_bytes());
    }
}
