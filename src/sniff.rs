//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    AudioAac,
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
    if is_adts_aac(data) {
        return Kind::AudioAac;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A bare ADTS AAC frame: 12-bit sync `1111 1111 1111`, then a fixed
/// `00` layer field with no equivalent in MPEG audio (which reserves that
/// layer value), so this never collides with an MP3 frame sync.
fn is_adts_aac(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xff && (data[1] & 0xf6) == 0xf0
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
    fn adts_frame_version_and_protection_bits_all_sniff_as_aac() {
        for byte1 in [0xf0u8, 0xf1, 0xf8, 0xf9] {
            let data = [0xff, byte1, 0x00, 0x00];
            assert_eq!(sniff(&data), Kind::AudioAac, "byte1 = {byte1:#04x}");
        }
    }

    #[test]
    fn mpeg_reserved_layer_is_not_aac() {
        // layer bits (0x06) set to a non-zero, non-AAC value
        assert_eq!(sniff(&[0xff, 0xf2, 0x00, 0x00]), Kind::Opaque);
    }

    #[test]
    fn short_buffer_is_not_aac() {
        assert_eq!(sniff(&[0xff]), Kind::Opaque);
    }

    #[test]
    fn non_sync_bytes_are_unaffected() {
        assert_eq!(sniff(b"hello particle"), Kind::Text);
    }
}
