//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    AudioMp3,
    AudioWav,
    AudioOgg,
    AudioFlac,
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
    if data.starts_with(b"fLaC") {
        return Kind::AudioFlac;
    }
    if data.len() >= 4 && &data[0..4] == b"OggS" {
        return Kind::AudioOgg;
    }
    if is_mp3(data) {
        return Kind::AudioMp3;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// An ID3v2 tag header, or a bare MPEG frame sync (11 set bits, layer/version
/// non-reserved). Real streams almost always carry the tag; the frame-sync
/// fallback catches tagless files.
fn is_mp3(data: &[u8]) -> bool {
    if data.len() >= 3 && &data[0..3] == b"ID3" {
        return true;
    }
    data.len() >= 2
        && data[0] == 0xff
        && (data[1] & 0xe0) == 0xe0
        && (data[1] & 0x18) != 0x08
        && (data[1] & 0x06) != 0x00
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
    fn wav_sniffed() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&data), Kind::AudioWav);
    }

    #[test]
    fn flac_sniffed() {
        let mut data = b"fLaC".to_vec();
        data.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&data), Kind::AudioFlac);
    }

    #[test]
    fn ogg_sniffed() {
        let mut data = b"OggS".to_vec();
        data.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&data), Kind::AudioOgg);
    }

    #[test]
    fn mp3_id3_sniffed() {
        let mut data = b"ID3".to_vec();
        data.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn mp3_frame_sync_sniffed() {
        // MPEG-1 Layer III frame header: sync + version 11 + layer 01 + no CRC.
        let data = [0xff, 0xfb, 0x90, 0x00, 0, 0, 0, 0];
        assert_eq!(sniff(&data), Kind::AudioMp3);
    }

    #[test]
    fn webp_still_sniffed_after_wav_added() {
        let mut data = b"RIFF".to_vec();
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(b"WEBP");
        data.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&data), Kind::ImageWebp);
    }

    #[test]
    fn short_riff_not_audio() {
        // Too short to read the WAVE/WEBP tag at offset 8..12 — must not panic.
        let data = [b'R', b'I', b'F', b'F', 0xff, 0xff, 0xff, 0xff];
        assert_eq!(sniff(&data), Kind::Opaque);
    }

    #[test]
    fn plain_text_not_mp3() {
        assert_eq!(sniff(b"just a line of words"), Kind::Text);
    }
}
