//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    VideoAvi,
    VideoMov,
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
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"AVI " {
        return Kind::VideoAvi;
    }
    if is_mov(data) {
        return Kind::VideoMov;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A `ftyp` ISOBMFF box whose major brand is QuickTime's own (`qt  `), the
/// one MP4-family brand that names a `.mov`, not an MP4/M4V/M4A file.
fn is_mov(data: &[u8]) -> bool {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return false;
    }
    &data[8..12] == b"qt  "
}

#[cfg(test)]
mod tests {
    use super::*;

    fn riff(fourcc: &[u8; 4]) -> Vec<u8> {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(fourcc);
        data.extend_from_slice(&[0; 8]);
        data
    }

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 20];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0; 8]);
        data
    }

    #[test]
    fn sniffs_avi() {
        assert_eq!(sniff(&riff(b"AVI ")), Kind::VideoAvi);
    }

    #[test]
    fn riff_wave_is_not_avi() {
        assert_eq!(sniff(&riff(b"WAVE")), Kind::Opaque);
    }

    #[test]
    fn sniffs_mov() {
        assert_eq!(sniff(&ftyp(b"qt  ")), Kind::VideoMov);
    }

    #[test]
    fn mp4_ftyp_is_not_mov() {
        assert_eq!(sniff(&ftyp(b"isom")), Kind::Opaque);
        assert_eq!(sniff(&ftyp(b"M4A ")), Kind::Opaque);
    }

    #[test]
    fn truncated_riff_is_not_avi() {
        assert_eq!(sniff(b"RIFF\0\0\0\0AV"), Kind::Opaque);
    }

    #[test]
    fn truncated_ftyp_is_not_mov() {
        assert!(!is_mov(b"\0\0\0\x14ftypq"));
    }
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
