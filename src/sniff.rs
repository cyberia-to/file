//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ArchiveGzip,
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
    // RFC 1952 member header: magic 1f 8b, deflate compression method 08.
    // A third byte outside {0..=8, reserved flag bits set} is not gzip.
    if data.len() >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08 {
        return Kind::ArchiveGzip;
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
    fn sniffs_gzip() {
        let data = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03];
        assert_eq!(sniff(&data), Kind::ArchiveGzip);
    }

    #[test]
    fn short_gzip_prefix_is_not_gzip() {
        assert_eq!(sniff(&[0x1f, 0x8b]), Kind::Opaque);
    }

    #[test]
    fn gzip_magic_with_unknown_compression_method_is_not_gzip() {
        // RFC 1952 defines only method 8 (deflate); anything else is not gzip.
        let data = [0x1f, 0x8b, 0x09, 0x00, 0, 0, 0, 0, 0, 0x03];
        assert_eq!(sniff(&data), Kind::Opaque);
    }
}
