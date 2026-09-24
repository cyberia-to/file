//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageIco,
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
    // ICONDIR: reserved = 0, type = 1 (icon, not 2 = cursor).
    if data.len() >= 6 && data[0..4] == [0x00, 0x00, 0x01, 0x00] {
        return Kind::ImageIco;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
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

    #[test]
    fn icondir_sniffs_as_ico() {
        assert_eq!(sniff(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00]), Kind::ImageIco);
    }

    #[test]
    fn cur_type_is_not_ico() {
        // Same reserved+magic shape, but type = 2 (cursor, not icon).
        assert_eq!(sniff(&[0x00, 0x00, 0x02, 0x00, 0x01, 0x00]), Kind::Opaque);
    }

    #[test]
    fn truncated_icondir_is_not_ico() {
        assert_eq!(sniff(&[0x00, 0x00, 0x01]), Kind::Opaque);
    }

    #[test]
    fn nonzero_reserved_is_not_ico() {
        assert_eq!(sniff(&[0x01, 0x00, 0x01, 0x00, 0x01, 0x00]), Kind::Opaque);
    }
}
