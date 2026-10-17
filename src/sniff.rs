//! Kind from magic bytes. Not a spark — just what the bytes look like.
//!
//! Every check reads a fixed header shape and never decodes, executes or
//! fetches. Weak signatures (two-byte magics, frame syncs, ASCII tags that
//! can open a sentence) are confirmed by a header field a real file always
//! carries, so ordinary text does not leave `Kind::Text`.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Json,
    Xml,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageBmp,
    ImageTiff,
    ImageIco,
    ImageSvg,
    /// HEIC, HEIF and AVIF stills (ISOBMFF `ftyp` image brands).
    ImageHeif,
    Pdf,
    DocumentRtf,
    /// Compound File Binary: pre-2007 .doc/.xls/.ppt, also .msi and .msg.
    DocumentLegacyOffice,
    VideoMp4,
    VideoWebm,
    VideoMkv,
    VideoMov,
    VideoAvi,
    VideoFlv,
    AudioMp3,
    AudioWav,
    AudioOgg,
    AudioFlac,
    AudioAac,
    AudioAiff,
    /// M4A, M4B and M4P (ISOBMFF `ftyp` audio brands).
    AudioM4a,
    /// TrueType outlines, including Apple `true` and `ttcf` collections.
    FontTtf,
    /// OpenType with CFF outlines (`OTTO`).
    FontOtf,
    FontWoff,
    FontWoff2,
    ArchiveGzip,
    ArchiveZstd,
    ArchiveTar,
    /// A ZIP container with none of the entries below.
    Zip,
    Docx,
    Xlsx,
    Pptx,
    Epub,
    Opaque,
}

/// ISOBMFF major brands of HEIC/HEIF/AVIF stills.
const HEIF_BRANDS: [&[u8; 4]; 8] = [
    b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1", b"avif",
];

/// ISOBMFF major brands of M4A/M4B/M4P audio.
const M4A_BRANDS: [&[u8; 4]; 3] = [b"M4A ", b"M4B ", b"M4P "];

/// Compound File Binary Format signature.
const CFB_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

const EBML_MAGIC: [u8; 4] = [0x1a, 0x45, 0xdf, 0xa3];

pub fn sniff(data: &[u8]) -> Kind {
    if data.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Kind::ImagePng;
    }
    if data.starts_with(&[0xff, 0xd8, 0xff]) {
        return Kind::ImageJpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Kind::ImageGif;
    }
    if let Some(kind) = sniff_riff(data) {
        return kind;
    }
    if is_bmp(data) {
        return Kind::ImageBmp;
    }
    if data.starts_with(b"II\x2a\x00") || data.starts_with(b"MM\x00\x2a") {
        return Kind::ImageTiff;
    }
    if is_ico(data) {
        return Kind::ImageIco;
    }
    if data.starts_with(b"%PDF-") {
        return Kind::Pdf;
    }
    if let Some(kind) = sniff_ftyp(data) {
        return kind;
    }
    if let Some(kind) = sniff_ebml(data) {
        return kind;
    }
    if is_flv(data) {
        return Kind::VideoFlv;
    }
    if data.len() >= 12 && &data[0..4] == b"FORM" && matches!(&data[8..12], b"AIFF" | b"AIFC") {
        return Kind::AudioAiff;
    }
    if data.starts_with(b"OggS") {
        return Kind::AudioOgg;
    }
    if data.starts_with(b"fLaC") {
        return Kind::AudioFlac;
    }
    if let Some(kind) = sniff_font(data) {
        return kind;
    }
    // RFC 1952 member header: magic 1f 8b, compression method 08 (deflate).
    if data.starts_with(&[0x1f, 0x8b, 0x08]) {
        return Kind::ArchiveGzip;
    }
    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Kind::ArchiveZstd;
    }
    if is_zip(data) {
        return sniff_zip_container(data);
    }
    if data.starts_with(&CFB_MAGIC) {
        return Kind::DocumentLegacyOffice;
    }
    // ADTS before MP3: both open with a frame sync, ADTS has layer 00,
    // which MPEG audio reserves.
    if is_adts_aac(data) {
        return Kind::AudioAac;
    }
    if is_mp3(data) {
        return Kind::AudioMp3;
    }
    if is_ustar(data) {
        return Kind::ArchiveTar;
    }
    // Text-shaped formats: checked ahead of `looks_like_text` so they get
    // their own kind instead of plain text.
    if data.starts_with(br"{\rtf1") {
        return Kind::DocumentRtf;
    }
    if is_svg(data) {
        return Kind::ImageSvg;
    }
    if is_xml(data) {
        return Kind::Xml;
    }
    if looks_like_text(data) {
        if looks_like_json(data) {
            return Kind::Json;
        }
        return Kind::Text;
    }
    Kind::Opaque
}

/// RIFF container: the form type at 8..12 names the format.
fn sniff_riff(data: &[u8]) -> Option<Kind> {
    if data.len() < 12 || &data[0..4] != b"RIFF" {
        return None;
    }
    match &data[8..12] {
        b"WEBP" => Some(Kind::ImageWebp),
        b"WAVE" => Some(Kind::AudioWav),
        b"AVI " => Some(Kind::VideoAvi),
        _ => None,
    }
}

/// `BM` alone is too weak a magic (two ASCII bytes collide with real text).
/// Confirm it by requiring the DIB header size field right after the
/// 14-byte file header to be one of the sizes a real BMP carries:
/// BITMAPCOREHEADER (12), BITMAPINFOHEADER (40), the V2/V3 extensions
/// (52, 56), OS/2 2.x (64), or BITMAPV4/V5HEADER (108, 124).
fn is_bmp(data: &[u8]) -> bool {
    if data.len() < 18 || &data[0..2] != b"BM" {
        return false;
    }
    let dib_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124)
}

/// ICONDIR: reserved 0, type 1 (icon; 2 is a cursor), at least one image.
fn is_ico(data: &[u8]) -> bool {
    data.len() >= 6
        && data[0..4] == [0x00, 0x00, 0x01, 0x00]
        && u16::from_le_bytes([data[4], data[5]]) != 0
}

/// ISOBMFF `ftyp` box: the major brand separates stills, audio, QuickTime
/// and the remaining MP4-family video.
fn sniff_ftyp(data: &[u8]) -> Option<Kind> {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return None;
    }
    let brand: &[u8; 4] = data[8..12].try_into().ok()?;
    if HEIF_BRANDS.contains(&brand) {
        Some(Kind::ImageHeif)
    } else if M4A_BRANDS.contains(&brand) {
        Some(Kind::AudioM4a)
    } else if brand == b"qt  " {
        Some(Kind::VideoMov)
    } else {
        Some(Kind::VideoMp4)
    }
}

/// EBML container: the header DocType tells WebM and Matroska apart, since
/// both share the container. Other or unreadable DocTypes are not claimed.
fn sniff_ebml(data: &[u8]) -> Option<Kind> {
    if !data.starts_with(&EBML_MAGIC) {
        return None;
    }
    let mut pos = 4usize;
    let (header_size, size_len) = read_vint_size(&data[pos..])?;
    pos = pos.checked_add(size_len)?;
    let header_end = pos
        .checked_add(usize::try_from(header_size).ok()?)?
        .min(data.len());
    while pos < header_end {
        let (id, id_len) = read_vint_id(&data[pos..])?;
        pos = pos.checked_add(id_len)?;
        let (size, size_len) = read_vint_size(&data[pos..])?;
        pos = pos.checked_add(size_len)?;
        let end = pos.checked_add(usize::try_from(size).ok()?)?;
        if end > data.len() {
            return None;
        }
        if id == 0x4282 {
            // DocType
            return match &data[pos..end] {
                b"webm" => Some(Kind::VideoWebm),
                b"matroska" => Some(Kind::VideoMkv),
                _ => None,
            };
        }
        pos = end;
    }
    None
}

/// EBML variable-size integer: length is one plus the leading zero bits
/// of the first byte; an all-zero first byte is reserved (invalid).
fn vint_len(first_byte: u8) -> Option<usize> {
    if first_byte == 0 {
        return None;
    }
    Some(first_byte.leading_zeros() as usize + 1)
}

/// Element size: marker bit stripped from the first byte.
fn read_vint_size(data: &[u8]) -> Option<(u64, usize)> {
    let len = vint_len(*data.first()?)?;
    if data.len() < len {
        return None;
    }
    let mask = 0xffu8 >> len;
    let mut value = (data[0] & mask) as u64;
    for &b in &data[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

/// Element ID: marker bit kept, it is part of the ID's identity.
fn read_vint_id(data: &[u8]) -> Option<(u32, usize)> {
    let len = vint_len(*data.first()?)?;
    if len > 4 || data.len() < len {
        return None;
    }
    let mut value = data[0] as u32;
    for &b in &data[1..len] {
        value = (value << 8) | b as u32;
    }
    Some((value, len))
}

/// FLV: `FLV`, version 1, a flags byte with only the audio/video bits,
/// then a 9-byte header size (big-endian u32).
fn is_flv(data: &[u8]) -> bool {
    if data.len() < 9 || &data[0..3] != b"FLV" || data[3] != 1 {
        return false;
    }
    if data[4] & 0xfa != 0 {
        return false;
    }
    u32::from_be_bytes([data[5], data[6], data[7], data[8]]) == 9
}

/// sfnt fonts and their WOFF wrappers. ASCII tags (`true`, `OTTO`, `ttcf`,
/// `wOFF`) can open a sentence, so each is confirmed by a binary field:
/// sfnt's table count, a collection's version, a wrapper's flavor.
fn sniff_font(data: &[u8]) -> Option<Kind> {
    if data.len() < 12 {
        return None;
    }
    let tag = &data[0..4];
    let next = &data[4..8];
    match tag {
        b"wOFF" | b"wOF2" if is_sfnt_flavor(next) => Some(if tag == b"wOFF" {
            Kind::FontWoff
        } else {
            Kind::FontWoff2
        }),
        b"ttcf" if next == [0, 1, 0, 0] || next == [0, 2, 0, 0] => Some(Kind::FontTtf),
        [0x00, 0x01, 0x00, 0x00] | b"true" | b"OTTO" => {
            let num_tables = u16::from_be_bytes([data[4], data[5]]);
            if !(1..=256).contains(&num_tables) {
                return None;
            }
            Some(if tag == b"OTTO" {
                Kind::FontOtf
            } else {
                Kind::FontTtf
            })
        }
        _ => None,
    }
}

fn is_sfnt_flavor(flavor: &[u8]) -> bool {
    matches!(
        flavor,
        [0x00, 0x01, 0x00, 0x00] | b"true" | b"OTTO" | b"ttcf"
    )
}

/// A ZIP local-file-header, empty-archive or spanned-archive signature.
fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
        || data.starts_with(&[0x50, 0x4b, 0x05, 0x06])
        || data.starts_with(&[0x50, 0x4b, 0x07, 0x08])
}

/// docx/xlsx/pptx/epub are ZIP archives distinguished only by the entry
/// names inside. Entry names sit in the plain (never-compressed) local file
/// header and central directory, so a literal search for the one entry each
/// format is defined by is enough; a real parse belongs to the opener.
fn sniff_zip_container(data: &[u8]) -> Kind {
    if contains(data, b"mimetypeapplication/epub+zip") {
        Kind::Epub
    } else if contains(data, b"word/document.xml") {
        Kind::Docx
    } else if contains(data, b"xl/workbook.xml") {
        Kind::Xlsx
    } else if contains(data, b"ppt/presentation.xml") {
        Kind::Pptx
    } else {
        Kind::Zip
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A bare ADTS AAC frame: 12-bit sync, layer `00` (reserved in MPEG audio,
/// so never an MP3 frame), a full 7-byte header and a defined sampling
/// frequency index (0..=12).
fn is_adts_aac(data: &[u8]) -> bool {
    data.len() >= 7 && data[0] == 0xff && (data[1] & 0xf6) == 0xf0 && ((data[2] >> 2) & 0x0f) < 13
}

/// An ID3v2 tag header, or a bare MPEG audio frame header with no reserved
/// field: version, layer, bitrate index and sampling rate all defined.
fn is_mp3(data: &[u8]) -> bool {
    if data.len() >= 10 && data.starts_with(b"ID3") {
        // major version 2..=4, revision not ff, syncsafe size bytes.
        return (2..=4).contains(&data[3])
            && data[4] != 0xff
            && data[6..10].iter().all(|&b| b < 0x80);
    }
    data.len() >= 4
        && data[0] == 0xff
        && (data[1] & 0xe0) == 0xe0
        && (data[1] & 0x18) != 0x08
        && (data[1] & 0x06) != 0x00
        && (data[2] >> 4) != 0x0f
        && (data[2] & 0x0c) != 0x0c
}

/// POSIX/GNU ustar header: `ustar` at offset 257 and a header checksum
/// (octal at 148..156) that matches the block, the checksum field itself
/// counted as spaces. The checksum keeps text that happens to carry
/// `ustar` at that offset out.
fn is_ustar(data: &[u8]) -> bool {
    if data.len() < 512 || &data[257..262] != b"ustar" {
        return false;
    }
    let block = &data[..512];
    let mut stored = 0u32;
    let mut digits = 0;
    for &b in &block[148..156] {
        match b {
            b'0'..=b'7' => {
                stored = stored * 8 + u32::from(b - b'0');
                digits += 1;
            }
            b' ' | 0 if digits == 0 => {}
            b' ' | 0 => break,
            _ => return false,
        }
    }
    if digits == 0 {
        return false;
    }
    let sum: u32 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20
            } else {
                u32::from(b)
            }
        })
        .sum();
    sum == stored
}

/// An SVG has no magic bytes: it is XML whose root element is `<svg`,
/// possibly behind a BOM, an `<?xml ... ?>` declaration, comments and a
/// doctype. This walks past those the way a browser sniffer does instead
/// of searching the buffer for the substring anywhere.
fn is_svg(data: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(data) else {
        return false;
    };
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();
    if rest.starts_with("<?xml") {
        let Some(end) = rest.find("?>") else {
            return false;
        };
        rest = rest[end + 2..].trim_start();
    }
    loop {
        if rest.starts_with("<!--") {
            let Some(end) = rest.find("-->") else {
                return false;
            };
            rest = rest[end + 3..].trim_start();
            continue;
        }
        if rest.len() >= 9 && rest.as_bytes()[..9].eq_ignore_ascii_case(b"<!doctype") {
            let Some(end) = rest.find('>') else {
                return false;
            };
            rest = rest[end + 1..].trim_start();
            continue;
        }
        break;
    }
    rest.len() >= 4 && rest.as_bytes()[..4].eq_ignore_ascii_case(b"<svg")
}

/// An XML declaration (`<?xml`) after an optional UTF-8 BOM and leading
/// whitespace. A bare tag with no declaration stays text.
fn is_xml(data: &[u8]) -> bool {
    let without_bom = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    without_bom.trim_ascii_start().starts_with(b"<?xml")
}

/// Whole-buffer structural check, not a parser: a single top-level `{...}`
/// or `[...]` with balanced, string-aware brackets and nothing but
/// whitespace outside them. An object also needs at least one quoted key
/// (unless it is empty), so prose that merely opens with `{` stays text;
/// a bare array of numbers still counts, since `[1, 2, 3]` has no string.
fn looks_like_json(data: &[u8]) -> bool {
    let Ok(s) = core::str::from_utf8(data) else {
        return false;
    };
    let trimmed = s.trim_start();
    let first = match trimmed.as_bytes().first() {
        Some(b @ (b'{' | b'[')) => *b,
        _ => return false,
    };

    let mut stack: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut escape = false;
    let mut saw_string = false;
    let mut close_idx = None;

    for (i, c) in trimmed.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                saw_string = true;
            }
            '{' => stack.push(b'{'),
            '[' => stack.push(b'['),
            '}' | ']' => {
                let open = if c == '}' { b'{' } else { b'[' };
                if stack.pop() != Some(open) {
                    return false;
                }
            }
            _ => {}
        }
        if stack.is_empty() && (c == '}' || c == ']') {
            close_idx = Some(i + c.len_utf8());
            break;
        }
    }

    let Some(close_idx) = close_idx else {
        return false;
    };
    if !trimmed[close_idx..].trim().is_empty() {
        return false;
    }
    let inner = trimmed[1..close_idx - 1].trim();
    !(first == b'{' && !inner.is_empty() && !saw_string)
}

fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if core::str::from_utf8(data).is_err() {
        return false;
    }
    let mut weird = 0usize;
    for &b in data {
        if b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b) {
            weird += 1;
        }
    }
    weird * 20 < data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(prefix: &[u8], pad: usize) -> Vec<u8> {
        let mut data = prefix.to_vec();
        data.extend(core::iter::repeat_n(0u8, pad));
        data
    }

    fn riff(form: &[u8; 4]) -> Vec<u8> {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&0x24u32.to_le_bytes());
        data.extend_from_slice(form);
        data.extend_from_slice(&[0; 16]);
        data
    }

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0; 16]);
        data
    }

    fn ebml(doctype: &[u8]) -> Vec<u8> {
        let mut header = vec![0x42, 0x82]; // DocType element ID
        header.push(0x80 | doctype.len() as u8); // 1-byte size vint
        header.extend_from_slice(doctype);
        let mut data = EBML_MAGIC.to_vec();
        data.push(0x80 | header.len() as u8); // 1-byte header-size vint
        data.extend_from_slice(&header);
        data
    }

    fn sfnt(tag: &[u8; 4], num_tables: u16) -> Vec<u8> {
        let mut data = tag.to_vec();
        data.extend_from_slice(&num_tables.to_be_bytes());
        data.extend_from_slice(&[0; 40]);
        data
    }

    fn ustar_block(magic: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[..8].copy_from_slice(b"file.txt");
        block[257..257 + magic.len()].copy_from_slice(magic);
        let sum: u32 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    0x20
                } else {
                    u32::from(b)
                }
            })
            .sum();
        let field = format!("{sum:06o}\0 ");
        block[148..156].copy_from_slice(field.as_bytes());
        block
    }

    // --- baseline -----------------------------------------------------

    #[test]
    fn text_and_opaque_baseline() {
        assert_eq!(sniff(b"a line of words"), Kind::Text);
        assert_eq!(sniff(&[]), Kind::Opaque);
        assert_eq!(sniff(&[0x80, 0x81, 0x82, 0x83]), Kind::Opaque);
    }

    // --- images -------------------------------------------------------

    #[test]
    fn webp_still_wins_over_wav_riff() {
        assert_eq!(sniff(&riff(b"WEBP")), Kind::ImageWebp);
    }

    #[test]
    fn short_riff_is_not_a_riff_kind() {
        let data = [b'R', b'I', b'F', b'F', 0xff, 0xff, 0xff, 0xff];
        assert_eq!(sniff(&data), Kind::Opaque);
        assert_eq!(sniff(b"RIFF\0\0\0\0AV"), Kind::Opaque);
    }

    fn bmp_header(dib_size: u32) -> Vec<u8> {
        let mut bytes = b"BM".to_vec();
        bytes.extend_from_slice(&[0u8; 12]); // file size, reserved, pixel offset
        bytes.extend_from_slice(&dib_size.to_le_bytes());
        bytes
    }

    #[test]
    fn bmp_by_dib_header_size() {
        for size in [12, 40, 108, 124] {
            assert_eq!(sniff(&bmp_header(size)), Kind::ImageBmp, "dib {size}");
        }
    }

    #[test]
    fn bm_prefixed_text_is_not_bmp() {
        let text = b"BMW cars are not bitmaps, this line is plain text.";
        assert_eq!(sniff(text), Kind::Text);
        assert_eq!(sniff(b"BM\x00\x00\x00\x00"), Kind::Opaque);
    }

    #[test]
    fn tiff_by_byte_order_magic() {
        assert_eq!(sniff(b"II\x2a\x00rest of the header"), Kind::ImageTiff);
        assert_eq!(sniff(b"MM\x00\x2arest of the header"), Kind::ImageTiff);
        assert_eq!(sniff(b"II\x01"), Kind::Opaque);
        assert_eq!(sniff(b"IIII\x2a\x00"), Kind::Opaque);
    }

    #[test]
    fn ico_by_icondir() {
        assert_eq!(sniff(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00]), Kind::ImageIco);
        // cursor type, truncated, nonzero reserved, zero images
        assert_eq!(sniff(&[0x00, 0x00, 0x02, 0x00, 0x01, 0x00]), Kind::Opaque);
        assert_eq!(sniff(&[0x00, 0x00, 0x01]), Kind::Opaque);
        assert_eq!(sniff(&[0x01, 0x00, 0x01, 0x00, 0x01, 0x00]), Kind::Opaque);
        assert_eq!(sniff(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]), Kind::Opaque);
    }

    #[test]
    fn svg_by_root_element() {
        assert_eq!(
            sniff(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
            Kind::ImageSvg
        );
        assert_eq!(
            sniff(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg></svg>"),
            Kind::ImageSvg
        );
        let doctype = b"<?xml version=\"1.0\"?>\n<!-- generated -->\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg></svg>";
        assert_eq!(sniff(doctype), Kind::ImageSvg);
        let mut bom = "\u{feff}".as_bytes().to_vec();
        bom.extend_from_slice(b"<svg></svg>");
        assert_eq!(sniff(&bom), Kind::ImageSvg);
        assert_eq!(sniff(b"<SVG></SVG>"), Kind::ImageSvg);
    }

    #[test]
    fn svg_needs_svg_root() {
        let nested = b"<?xml version=\"1.0\"?>\n<root><svg>not the root</svg></root>";
        assert_eq!(sniff(nested), Kind::Xml);
        assert_eq!(
            sniff(b"please attach an <svg> file to this email"),
            Kind::Text
        );
        assert_ne!(sniff(b"<?xml version=\"1.0\""), Kind::ImageSvg);
    }

    #[test]
    fn heif_by_ftyp_brand() {
        assert_eq!(sniff(&ftyp(b"heic")), Kind::ImageHeif);
        assert_eq!(sniff(&ftyp(b"avif")), Kind::ImageHeif);
        assert_eq!(sniff(&ftyp(b"mif1")), Kind::ImageHeif);
    }

    // --- documents ----------------------------------------------------

    #[test]
    fn sniffs_pdf() {
        let mut data = b"%PDF-1.7\n".to_vec();
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::Pdf);
    }

    #[test]
    fn rtf_by_control_word_preamble() {
        assert_eq!(
            sniff(br"{\rtf1\ansi\deff0 Hello, world!}"),
            Kind::DocumentRtf
        );
        assert_eq!(sniff(br"{\rtf and then some prose}"), Kind::Text);
    }

    #[test]
    fn cfb_by_magic() {
        assert_eq!(sniff(&padded(&CFB_MAGIC, 24)), Kind::DocumentLegacyOffice);
        assert_eq!(sniff(&CFB_MAGIC[..4]), Kind::Opaque);
        let mut wrong = CFB_MAGIC;
        wrong[7] = 0xe2;
        assert_eq!(sniff(&wrong), Kind::Opaque);
    }

    #[test]
    fn json_objects_and_arrays() {
        assert_eq!(sniff(br#"{"particle": "hemera", "n": 3}"#), Kind::Json);
        assert_eq!(
            sniff(br#" { "a": [1, 2, {"b": "c\"d"}], "e": null} "#),
            Kind::Json
        );
        assert_eq!(sniff(b"{}"), Kind::Json);
        assert_eq!(sniff(b"[]"), Kind::Json);
        assert_eq!(sniff(b"[1, 2, 3]"), Kind::Json);
    }

    #[test]
    fn json_lookalikes_stay_text() {
        assert_eq!(sniff(b"{ this is not json, just a note }"), Kind::Text);
        assert_eq!(sniff(br#"{"a": 1"#), Kind::Text);
        assert_eq!(sniff(br#"{"a": 1} and then some prose"#), Kind::Text);
        assert_eq!(sniff(b"{ just a json-looking line }"), Kind::Text);
    }

    #[test]
    fn xml_by_declaration() {
        assert_eq!(sniff(b"<?xml version=\"1.0\"?><root/>"), Kind::Xml);
        assert_eq!(sniff(b"\n  \t<?xml version=\"1.0\"?><root/>"), Kind::Xml);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(b"<?xml version=\"1.0\"?><root/>");
        assert_eq!(sniff(&bom), Kind::Xml);
        assert_eq!(sniff(b"<root><child/></root>"), Kind::Text);
        assert_eq!(sniff(b"<?xm not quite"), Kind::Text);
    }

    // --- video --------------------------------------------------------

    #[test]
    fn ftyp_brands_split_mp4_mov_m4a() {
        assert_eq!(sniff(&ftyp(b"isom")), Kind::VideoMp4);
        assert_eq!(sniff(&ftyp(b"mp42")), Kind::VideoMp4);
        assert_eq!(sniff(&ftyp(b"M4V ")), Kind::VideoMp4);
        assert_eq!(sniff(&ftyp(b"qt  ")), Kind::VideoMov);
        assert_eq!(sniff(&ftyp(b"M4A ")), Kind::AudioM4a);
        assert_eq!(sniff(&ftyp(b"M4B ")), Kind::AudioM4a);
        assert_eq!(sniff(&ftyp(b"M4P ")), Kind::AudioM4a);
    }

    #[test]
    fn truncated_ftyp_is_not_claimed() {
        assert_eq!(sniff_ftyp(b"ftyp"), None);
        assert_eq!(sniff_ftyp(b"\0\0\0\x18ftypis"), None);
    }

    #[test]
    fn ebml_doctype_splits_webm_and_mkv() {
        assert_eq!(sniff(&ebml(b"webm")), Kind::VideoWebm);
        assert_eq!(sniff(&ebml(b"matroska")), Kind::VideoMkv);
        assert_eq!(sniff(&ebml(b"quicktime")), Kind::Opaque);
    }

    #[test]
    fn truncated_ebml_does_not_panic() {
        assert_eq!(sniff(&EBML_MAGIC), Kind::Opaque);
        assert_eq!(sniff(&[0x1a, 0x45, 0xdf, 0xa3, 0x87, 0x42]), Kind::Opaque);
        assert_eq!(sniff(&[0x1a, 0x45, 0xdf, 0xa3, 0x01]), Kind::Opaque);
        assert_eq!(sniff(&padded(&EBML_MAGIC, 16)), Kind::Opaque);
    }

    #[test]
    fn avi_by_riff_form() {
        assert_eq!(sniff(&riff(b"AVI ")), Kind::VideoAvi);
    }

    fn flv_header(video: bool, audio: bool, header_size: u32) -> Vec<u8> {
        let flags = if audio { 0x04 } else { 0 } | if video { 0x01 } else { 0 };
        let mut data = vec![b'F', b'L', b'V', 1, flags];
        data.extend_from_slice(&header_size.to_be_bytes());
        data
    }

    #[test]
    fn flv_by_header() {
        assert_eq!(sniff(&flv_header(true, true, 9)), Kind::VideoFlv);
        assert_eq!(sniff(&flv_header(true, false, 9)), Kind::VideoFlv);
        assert_ne!(sniff(&flv_header(true, true, 11)), Kind::VideoFlv);
        let mut reserved = flv_header(true, true, 9);
        reserved[4] |= 0x08;
        assert_ne!(sniff(&reserved), Kind::VideoFlv);
        assert_eq!(sniff(b"FLV"), Kind::Text);
        assert_eq!(sniff(b"FLV files are common"), Kind::Text);
    }

    // --- audio --------------------------------------------------------

    #[test]
    fn sniffs_wav() {
        assert_eq!(sniff(&riff(b"WAVE")), Kind::AudioWav);
    }

    #[test]
    fn sniffs_ogg() {
        // OggS, stream structure version 0, header type 0x02 (BOS), granule 0.
        assert_eq!(sniff(&padded(b"OggS\x00\x02", 20)), Kind::AudioOgg);
    }

    #[test]
    fn sniffs_flac() {
        // fLaC then the STREAMINFO block header 00 00 00 22.
        assert_eq!(sniff(&padded(b"fLaC\x00\x00\x00\x22", 16)), Kind::AudioFlac);
    }

    #[test]
    fn mp3_by_id3_tag() {
        assert_eq!(sniff(b"ID3\x03\x00\x00\x00\x00\x00\x00"), Kind::AudioMp3);
        assert_eq!(sniff(&padded(b"ID3\x04\x00\x00", 16)), Kind::AudioMp3);
        assert_eq!(sniff(b"ID3 tags carry the title and artist"), Kind::Text);
    }

    #[test]
    fn mp3_by_frame_header() {
        // MPEG-1 Layer III, 128 kbit/s, 44.1 kHz.
        assert_eq!(sniff(&[0xff, 0xfb, 0x90, 0x00, 0, 0, 0, 0]), Kind::AudioMp3);
        assert_eq!(sniff(&padded(&[0xff, 0xfb], 16)), Kind::AudioMp3);
        // MPEG-2 Layer III
        assert_eq!(sniff(&[0xff, 0xf2, 0x00, 0x00]), Kind::AudioMp3);
        // bad bitrate index, reserved sampling rate
        assert_eq!(sniff(&[0xff, 0xfb, 0xf0, 0x00]), Kind::Opaque);
        assert_eq!(sniff(&[0xff, 0xfb, 0x0c, 0x00]), Kind::Opaque);
    }

    #[test]
    fn jpeg_is_not_an_mpeg_frame() {
        assert_eq!(
            sniff(&padded(&[0xff, 0xd8, 0xff, 0xe0], 16)),
            Kind::ImageJpeg
        );
    }

    #[test]
    fn adts_aac_by_frame_sync() {
        for byte1 in [0xf0u8, 0xf1, 0xf8, 0xf9] {
            let data = [0xff, byte1, 0x50, 0x80, 0x00, 0x1f, 0xfc];
            assert_eq!(sniff(&data), Kind::AudioAac, "byte1 = {byte1:#04x}");
        }
        // sampling frequency index 15 is reserved
        assert_ne!(
            sniff(&[0xff, 0xf1, 0x3c, 0x80, 0x00, 0x1f, 0xfc]),
            Kind::AudioAac
        );
        assert_eq!(sniff(&[0xff]), Kind::Opaque);
    }

    #[test]
    fn aiff_by_form_type() {
        let mut aiff = b"FORM\x00\x00\x00\x2aAIFF".to_vec();
        aiff.extend_from_slice(b"COMMextra bytes");
        assert_eq!(sniff(&aiff), Kind::AudioAiff);
        assert_eq!(
            sniff(b"FORM\x00\x00\x01\x00AIFCrestofthefile"),
            Kind::AudioAiff
        );
        assert_ne!(sniff(b"FORM\x00\x00\x00\x04ILBM"), Kind::AudioAiff);
        assert_ne!(sniff(b"FORM"), Kind::AudioAiff);
    }

    // --- fonts --------------------------------------------------------

    #[test]
    fn sfnt_fonts_by_version_tag() {
        assert_eq!(sniff(&sfnt(&[0x00, 0x01, 0x00, 0x00], 12)), Kind::FontTtf);
        assert_eq!(sniff(&sfnt(b"true", 12)), Kind::FontTtf);
        assert_eq!(sniff(&sfnt(b"OTTO", 12)), Kind::FontOtf);
        assert_eq!(sniff(&padded(b"ttcf\x00\x01\x00\x00", 40)), Kind::FontTtf);
    }

    #[test]
    fn sfnt_tags_opening_a_sentence_stay_text() {
        assert_eq!(sniff(b"true story: the font was never there"), Kind::Text);
        assert_eq!(sniff(b"OTTO von Bismarck, a biography"), Kind::Text);
        assert_eq!(sniff(b"ttcf is a collection tag"), Kind::Text);
        assert_ne!(sniff(&sfnt(&[0x00, 0x01, 0x00, 0x01], 12)), Kind::FontTtf);
        assert_ne!(sniff(&sfnt(b"true", 0)), Kind::FontTtf);
    }

    #[test]
    fn woff_by_magic_and_flavor() {
        assert_eq!(sniff(&padded(b"wOFF\x00\x01\x00\x00", 40)), Kind::FontWoff);
        assert_eq!(sniff(&padded(b"wOF2OTTO", 40)), Kind::FontWoff2);
        assert_ne!(sniff(&padded(b"wOFf\x00\x01\x00\x00", 40)), Kind::FontWoff);
        assert_eq!(sniff(b"wOFF is the magic of a web font"), Kind::Text);
    }

    // --- archives -----------------------------------------------------

    #[test]
    fn gzip_by_member_header() {
        assert_eq!(
            sniff(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03]),
            Kind::ArchiveGzip
        );
        assert_eq!(sniff(&[0x1f, 0x8b]), Kind::Opaque);
        assert_eq!(
            sniff(&[0x1f, 0x8b, 0x09, 0x00, 0, 0, 0, 0, 0, 0x03]),
            Kind::Opaque
        );
    }

    #[test]
    fn zstd_by_frame_magic() {
        assert_eq!(
            sniff(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x00, 0x00]),
            Kind::ArchiveZstd
        );
        assert_eq!(sniff(&[0x28, 0xb5, 0x2f]), Kind::Opaque);
        // skippable frame magic, not a data frame
        assert_eq!(
            sniff(&[0x50, 0x2a, 0x4d, 0x18, 0x00, 0x00, 0x00, 0x00]),
            Kind::Opaque
        );
    }

    #[test]
    fn tar_by_ustar_header() {
        assert_eq!(sniff(&ustar_block(b"ustar\x0000")), Kind::ArchiveTar);
        assert_eq!(sniff(&ustar_block(b"ustar  \0")), Kind::ArchiveTar);
        let mut short = ustar_block(b"ustar\0");
        short.truncate(511);
        assert_eq!(sniff(&short), Kind::Opaque);
        assert_eq!(sniff(&[0u8; 512]), Kind::Opaque);
        let mut bad_sum = ustar_block(b"ustar\0");
        bad_sum[0] = b'g';
        assert_eq!(sniff(&bad_sum), Kind::Opaque);
    }

    #[test]
    fn text_with_ustar_at_offset_257_stays_text() {
        let mut text = vec![b'a'; 600];
        text[257..262].copy_from_slice(b"ustar");
        assert_eq!(sniff(&text), Kind::Text);
    }

    fn zip_containing(entry_name: &[u8]) -> Vec<u8> {
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(entry_name);
        data
    }

    #[test]
    fn zip_and_its_document_formats() {
        assert_eq!(sniff(&zip_containing(b"readme.txt")), Kind::Zip);
        assert_eq!(
            sniff(&zip_containing(b"mimetypeapplication/epub+zip")),
            Kind::Epub
        );
        assert_eq!(sniff(&zip_containing(b"word/document.xml")), Kind::Docx);
        assert_eq!(sniff(&zip_containing(b"xl/workbook.xml")), Kind::Xlsx);
        assert_eq!(sniff(&zip_containing(b"ppt/presentation.xml")), Kind::Pptx);
        assert_eq!(sniff(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]), Kind::Zip);
        assert_eq!(sniff(&[0x50, 0x4b, 0x07, 0x08, 0, 0, 0, 0]), Kind::Zip);
        assert!(!is_zip(&[0x50, 0x4b, 0x03]));
        assert_eq!(sniff(b"PKthis is just some text"), Kind::Text);
    }
}
