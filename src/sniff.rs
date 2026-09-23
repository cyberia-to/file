//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageTiff,
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
    if data.len() >= 4 && (&data[0..4] == b"II\x2a\x00" || &data[0..4] == b"MM\x00\x2a") {
        return Kind::ImageTiff;
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
    fn little_endian_tiff_sniffs_as_tiff() {
        assert_eq!(sniff(b"II\x2a\x00rest of the header"), Kind::ImageTiff);
    }

    #[test]
    fn big_endian_tiff_sniffs_as_tiff() {
        assert_eq!(sniff(b"MM\x00\x2arest of the header"), Kind::ImageTiff);
    }

    #[test]
    fn truncated_tiff_prefix_is_not_tiff() {
        // Three bytes can't carry the four-byte TIFF magic; a trailing
        // control byte keeps it from being misread as plain text either.
        assert_eq!(sniff(b"II\x01"), Kind::Opaque);
    }

    #[test]
    fn wrong_byte_order_marker_is_not_tiff() {
        assert_eq!(sniff(b"IIII\x2a\x00"), Kind::Opaque);
    }
}
