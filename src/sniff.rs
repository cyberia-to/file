//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageBmp,
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
    if looks_like_bmp(data) {
        return Kind::ImageBmp;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// `BM` alone is too weak a magic (two ASCII bytes collide with real text).
/// Confirm it by requiring the DIB header size field right after the
/// 14-byte file header to be one of the handful of sizes any real BMP
/// carries — BITMAPCOREHEADER (12), BITMAPINFOHEADER (40), the V2/V3
/// extensions (52, 56), OS/2 2.x (64), or BITMAPV4/V5HEADER (108, 124).
fn looks_like_bmp(data: &[u8]) -> bool {
    if data.len() < 18 || &data[0..2] != b"BM" {
        return false;
    }
    let dib_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    matches!(dib_size, 12 | 40 | 52 | 56 | 64 | 108 | 124)
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

    fn bmp_header(dib_size: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BM");
        bytes.extend_from_slice(&[0u8; 4]); // file size, unchecked by sniff
        bytes.extend_from_slice(&[0u8; 4]); // reserved
        bytes.extend_from_slice(&[0u8; 4]); // pixel data offset, unchecked by sniff
        bytes.extend_from_slice(&dib_size.to_le_bytes());
        bytes
    }

    #[test]
    fn bitmapinfoheader_sniffs_as_bmp() {
        assert_eq!(sniff(&bmp_header(40)), Kind::ImageBmp);
    }

    #[test]
    fn bitmapcoreheader_sniffs_as_bmp() {
        assert_eq!(sniff(&bmp_header(12)), Kind::ImageBmp);
    }

    #[test]
    fn v4_and_v5_headers_sniff_as_bmp() {
        assert_eq!(sniff(&bmp_header(108)), Kind::ImageBmp);
        assert_eq!(sniff(&bmp_header(124)), Kind::ImageBmp);
    }

    #[test]
    fn bm_prefixed_text_with_unknown_dib_size_is_not_bmp() {
        // Two ASCII bytes are too weak a magic on their own; a real
        // sentence starting "BM" must not misclassify as an image.
        let text = b"BMW cars are not bitmaps, this line is plain text.";
        assert_eq!(sniff(text), Kind::Text);
    }

    #[test]
    fn truncated_bm_prefix_is_not_bmp() {
        assert_eq!(sniff(b"BM\x00\x00\x00\x00"), Kind::Opaque);
    }
}
