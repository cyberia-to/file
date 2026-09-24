//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    AudioAiff,
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
    if data.len() >= 12 && &data[0..4] == b"FORM" && (&data[8..12] == b"AIFF" || &data[8..12] == b"AIFC") {
        return Kind::AudioAiff;
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
    fn sniffs_aiff() {
        let mut data = b"FORM".to_vec();
        data.extend_from_slice(&[0, 0, 0, 42]); // chunk size, irrelevant here
        data.extend_from_slice(b"AIFF");
        data.extend_from_slice(b"COMMextra bytes");
        assert_eq!(sniff(&data), Kind::AudioAiff);
    }

    #[test]
    fn sniffs_aifc() {
        let mut data = b"FORM".to_vec();
        data.extend_from_slice(&[0, 0, 1, 0]);
        data.extend_from_slice(b"AIFC");
        data.extend_from_slice(b"restofthefile");
        assert_eq!(sniff(&data), Kind::AudioAiff);
    }

    #[test]
    fn rejects_other_form_containers() {
        // FORM-based RIFF-like container that is not AIFF/AIFC (e.g. a
        // hypothetical unrelated IFF format) must not be sniffed as audio.
        let mut data = b"FORM".to_vec();
        data.extend_from_slice(&[0, 0, 0, 4]);
        data.extend_from_slice(b"ILBM");
        assert_ne!(sniff(&data), Kind::AudioAiff);
    }

    #[test]
    fn short_form_prefix_is_not_aiff() {
        // Fewer than 12 bytes: too short to read the form-type field at all.
        let data = b"FORM".to_vec();
        assert_ne!(sniff(&data), Kind::AudioAiff);
    }
}
