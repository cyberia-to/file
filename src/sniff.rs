//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    Pdf,
    VideoMp4,
    VideoWebm,
    AudioMp3,
    AudioWav,
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
    if data.starts_with(b"%PDF-") {
        return Kind::Pdf;
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Kind::VideoMp4;
    }
    if data.len() >= 4 && &data[0..4] == &[0x1a, 0x45, 0xdf, 0xa3] {
        return Kind::VideoWebm;
    }
    if data.len() >= 3 && (data.starts_with(b"ID3") || (data[0] == 0xff && data[1] & 0xe0 == 0xe0))
    {
        return Kind::AudioMp3;
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
    fn sniffs_pdf() {
        let mut data = b"%PDF-1.7\n".to_vec();
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::Pdf);
    }

    #[test]
    fn sniffs_mp4() {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftypisom");
        data.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&data), Kind::VideoMp4);
    }

    #[test]
    fn sniffs_webm() {
        let mut data = vec![0x1a, 0x45, 0xdf, 0xa3];
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::VideoWebm);
    }

    #[test]
    fn sniffs_wav() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WAVE");
        assert_eq!(sniff(&data), Kind::AudioWav);
    }

    #[test]
    fn sniffs_mp3_id3() {
        let mut data = b"ID3".to_vec();
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn sniffs_mp3_frame_sync() {
        let mut data = vec![0xff, 0xfb];
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn webp_still_wins_over_wav_riff() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WEBP");
        assert_eq!(sniff(&data), Kind::ImageWebp);
    }
}
