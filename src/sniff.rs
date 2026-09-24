//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    AudioM4a,
    Opaque,
}

/// ISOBMFF major brands that mark a `ftyp` box as M4A/M4B audio, not the
/// video (MP4/M4V) or still-image (HEIC/HEIF/AVIF) brands the same
/// container shape also carries.
const M4A_BRANDS: [&[u8; 4]; 3] = [b"M4A ", b"M4B ", b"M4P "];

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
    if is_m4a(data) {
        return Kind::AudioM4a;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A `ftyp` ISOBMFF box whose major brand names M4A/M4B/M4P audio.
fn is_m4a(data: &[u8]) -> bool {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return false;
    }
    let brand: &[u8; 4] = match data[8..12].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    M4A_BRANDS.contains(&brand)
}

#[cfg(test)]
mod m4a_tests {
    use super::*;

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0; 16]);
        data
    }

    #[test]
    fn sniffs_m4a() {
        assert_eq!(sniff(&ftyp(b"M4A ")), Kind::AudioM4a);
    }

    #[test]
    fn sniffs_m4b_audiobook() {
        assert_eq!(sniff(&ftyp(b"M4B ")), Kind::AudioM4a);
    }

    #[test]
    fn sniffs_m4p_protected() {
        assert_eq!(sniff(&ftyp(b"M4P ")), Kind::AudioM4a);
    }

    #[test]
    fn mp4_video_brand_is_not_m4a() {
        assert_eq!(sniff(&ftyp(b"isom")), Kind::Opaque);
    }

    #[test]
    fn heic_brand_is_not_m4a() {
        assert_eq!(sniff(&ftyp(b"heic")), Kind::Opaque);
    }

    #[test]
    fn short_ftyp_is_not_m4a() {
        assert!(!is_m4a(b"ftyp"));
    }

    #[test]
    fn truncated_ftyp_box_is_not_m4a() {
        assert!(!is_m4a(b"\0\0\0\x18ftypis"));
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
