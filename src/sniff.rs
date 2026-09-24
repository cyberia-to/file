//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    AudioWav,
    AudioMp3,
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
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return Kind::AudioWav;
    }
    if is_mp3(data) {
        return Kind::AudioMp3;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// An ID3v2 tag, or a raw MPEG audio frame sync (11 set high bits).
fn is_mp3(data: &[u8]) -> bool {
    if data.starts_with(b"ID3") {
        return true;
    }
    data.len() >= 2 && data[0] == 0xff && (data[1] & 0xe0) == 0xe0
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
    fn wav_by_riff_wave() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(b"fmt ");
        assert_eq!(sniff(&data), Kind::AudioWav);
    }

    #[test]
    fn riff_without_wave_is_not_wav() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WEBP");
        assert_eq!(sniff(&data), Kind::ImageWebp);
    }

    #[test]
    fn mp3_by_id3_tag() {
        let mut data = b"ID3".to_vec();
        data.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn mp3_by_raw_frame_sync() {
        let data = [0xff, 0xfb, 0x90, 0x00, 0x00, 0x00];
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn jpeg_not_confused_with_mp3_frame_sync() {
        let data = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
        assert_eq!(sniff(&data), Kind::ImageJpeg);
    }

    #[test]
    fn short_input_is_not_wav_or_mp3() {
        assert_eq!(sniff(&[0xff]), Kind::Opaque);
        assert_eq!(sniff(b"RIFF"), Kind::Text);
    }
}
