//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    VideoFlv,
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
    if is_flv(data) {
        return Kind::VideoFlv;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// FLV: `"FLV"`, version 1, a flags byte with only the audio/video
/// present bits set, then a 9-byte header size (big-endian u32).
/// The header-size and reserved-bits checks rule out plain text that
/// happens to start with the three-byte tag.
fn is_flv(data: &[u8]) -> bool {
    if data.len() < 9 || &data[0..3] != b"FLV" || data[3] != 1 {
        return false;
    }
    if data[4] & 0xFA != 0 {
        return false;
    }
    u32::from_be_bytes([data[5], data[6], data[7], data[8]]) == 9
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

    fn flv_header(video: bool, audio: bool, header_size: u32) -> Vec<u8> {
        let mut flags = 0u8;
        if audio {
            flags |= 0x04;
        }
        if video {
            flags |= 0x01;
        }
        let mut data = vec![b'F', b'L', b'V', 1, flags];
        data.extend_from_slice(&header_size.to_be_bytes());
        data
    }

    #[test]
    fn flv_with_video_and_audio_sniffs_as_video_flv() {
        assert_eq!(sniff(&flv_header(true, true, 9)), Kind::VideoFlv);
    }

    #[test]
    fn flv_video_only_sniffs_as_video_flv() {
        assert_eq!(sniff(&flv_header(true, false, 9)), Kind::VideoFlv);
    }

    #[test]
    fn wrong_header_size_is_not_flv() {
        assert_ne!(sniff(&flv_header(true, true, 11)), Kind::VideoFlv);
    }

    #[test]
    fn reserved_flag_bits_set_is_not_flv() {
        let mut data = flv_header(true, true, 9);
        data[4] |= 0x08;
        assert_ne!(sniff(&data), Kind::VideoFlv);
    }

    #[test]
    fn short_flv_prefix_does_not_panic() {
        assert_eq!(sniff(b"FLV"), Kind::Text);
        assert_eq!(sniff(&[b'F', b'L', b'V', 1]), Kind::Opaque);
    }

    #[test]
    fn plain_text_starting_with_flv_is_still_text() {
        assert_eq!(sniff(b"FLV files are common"), Kind::Text);
    }
}
