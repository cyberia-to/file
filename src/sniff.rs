//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    VideoWebm,
    Opaque,
}

pub fn sniff(data: &[u8]) -> Kind {
    if data.len() >= 8 && data.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Kind::ImagePng;
    }
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return Kind::ImageJpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Kind::ImageGif;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Kind::ImageWebp;
    }
    if let Some(kind) = sniff_ebml(data) {
        return kind;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// EBML container (magic `1A 45 DF A3`) whose header DocType is `webm`.
/// Matroska itself (DocType `matroska`) and any other EBML doc type is
/// left undetected here — plain video/audio kinds only.
fn sniff_ebml(data: &[u8]) -> Option<Kind> {
    if data.len() < 4 || data[0..4] != [0x1A, 0x45, 0xDF, 0xA3] {
        return None;
    }
    let mut pos = 4usize;
    let (header_size, size_len) = read_vint_size(&data[pos..])?;
    pos = pos.checked_add(size_len)?;
    let header_end = pos.checked_add(header_size as usize)?.min(data.len());
    while pos < header_end {
        let (id, id_len) = read_vint_id(&data[pos..])?;
        pos = pos.checked_add(id_len)?;
        let (size, size_len) = read_vint_size(&data[pos..])?;
        pos = pos.checked_add(size_len)?;
        let size = size as usize;
        let end = pos.checked_add(size)?;
        if end > data.len() {
            return None;
        }
        if id == 0x4282 {
            // DocType
            return if &data[pos..end] == b"webm" {
                Some(Kind::VideoWebm)
            } else {
                None
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
    let mask = 0xFFu8 >> len;
    let mut value = (data[0] & mask) as u64;
    for &b in &data[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

/// Element ID: marker bit kept, it is part of the ID's identity.
fn read_vint_id(data: &[u8]) -> Option<(u32, usize)> {
    let len = vint_len(*data.first()?)?;
    if data.len() < len {
        return None;
    }
    let mut value = data[0] as u32;
    for &b in &data[1..len] {
        value = (value << 8) | b as u32;
    }
    Some((value, len))
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

    fn ebml(doctype: &[u8]) -> Vec<u8> {
        let mut header = vec![0x42, 0x82]; // DocType element ID
        header.push(0x80 | doctype.len() as u8); // 1-byte size vint
        header.extend_from_slice(doctype);
        let mut data = vec![0x1A, 0x45, 0xDF, 0xA3];
        data.push(0x80 | header.len() as u8); // 1-byte header-size vint
        data.extend_from_slice(&header);
        data
    }

    #[test]
    fn webm_doctype_sniffs_as_video_webm() {
        assert_eq!(sniff(&ebml(b"webm")), Kind::VideoWebm);
    }

    #[test]
    fn matroska_doctype_is_not_webm() {
        assert_ne!(sniff(&ebml(b"matroska")), Kind::VideoWebm);
    }

    #[test]
    fn truncated_ebml_does_not_panic() {
        assert_eq!(sniff(&[0x1A, 0x45, 0xDF, 0xA3]), Kind::Opaque);
        assert_eq!(sniff(&[0x1A, 0x45, 0xDF, 0xA3, 0x87, 0x42]), Kind::Opaque);
    }

    #[test]
    fn oversized_ebml_size_does_not_overflow() {
        assert_eq!(sniff(&[0x1A, 0x45, 0xDF, 0xA3, 0x01]), Kind::Opaque);
    }

    #[test]
    fn non_ebml_bytes_are_unaffected() {
        assert_eq!(sniff(b"hello particle"), Kind::Text);
    }
}
