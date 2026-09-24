//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    FontTtf,
    FontOtf,
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
    if data.starts_with(&[0x00, 0x01, 0x00, 0x00]) || data.starts_with(b"true") || data.starts_with(b"ttcf") {
        return Kind::FontTtf;
    }
    if data.starts_with(b"OTTO") {
        return Kind::FontOtf;
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
    fn sniffs_ttf_by_sfnt_version() {
        let mut data = vec![0x00, 0x01, 0x00, 0x00];
        data.extend_from_slice(&[0; 40]);
        assert_eq!(sniff(&data), Kind::FontTtf);
    }

    #[test]
    fn sniffs_ttf_by_apple_true_tag() {
        let mut data = b"true".to_vec();
        data.extend_from_slice(&[0; 40]);
        assert_eq!(sniff(&data), Kind::FontTtf);
    }

    #[test]
    fn sniffs_ttf_collection() {
        let mut data = b"ttcf".to_vec();
        data.extend_from_slice(&[0; 40]);
        assert_eq!(sniff(&data), Kind::FontTtf);
    }

    #[test]
    fn sniffs_otf() {
        let mut data = b"OTTO".to_vec();
        data.extend_from_slice(&[0; 40]);
        assert_eq!(sniff(&data), Kind::FontOtf);
    }

    #[test]
    fn near_miss_sfnt_version_is_not_a_font() {
        let mut data = vec![0x00, 0x01, 0x00, 0x01]; // not the exact sfnt version tag
        data.extend_from_slice(&[0; 40]);
        assert_ne!(sniff(&data), Kind::FontTtf);
    }
}
