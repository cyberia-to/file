//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    VideoMp4,
    Opaque,
}

/// ISOBMFF major brands that mark a `ftyp` box as MP4/M4V video, not the
/// still-image (HEIC/HEIF/AVIF) or QuickTime-native (`qt  `) brands the same
/// container shape also carries.
const MP4_BRANDS: [&[u8; 4]; 9] = [
    b"isom", b"iso2", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1", b"M4V ", b"dash",
];

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
    if is_mp4(data) {
        return Kind::VideoMp4;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A `ftyp` ISOBMFF box whose major brand names MP4/M4V video.
fn is_mp4(data: &[u8]) -> bool {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return false;
    }
    let brand: &[u8; 4] = match data[8..12].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    MP4_BRANDS.contains(&brand)
}

#[cfg(test)]
mod mp4_tests {
    use super::*;

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0; 16]);
        data
    }

    #[test]
    fn sniffs_isom() {
        assert_eq!(sniff(&ftyp(b"isom")), Kind::VideoMp4);
    }

    #[test]
    fn sniffs_mp42() {
        assert_eq!(sniff(&ftyp(b"mp42")), Kind::VideoMp4);
    }

    #[test]
    fn sniffs_m4v() {
        assert_eq!(sniff(&ftyp(b"M4V ")), Kind::VideoMp4);
    }

    #[test]
    fn qt_brand_is_not_mp4() {
        assert_eq!(sniff(&ftyp(b"qt  ")), Kind::Opaque);
    }

    #[test]
    fn heic_brand_is_not_mp4() {
        assert_eq!(sniff(&ftyp(b"heic")), Kind::Opaque);
    }

    #[test]
    fn short_ftyp_is_not_mp4() {
        assert!(!is_mp4(b"ftyp"));
    }

    #[test]
    fn truncated_ftyp_box_is_not_mp4() {
        assert!(!is_mp4(b"\0\0\0\x18ftypis"));
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
