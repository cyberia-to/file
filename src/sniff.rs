//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    DocumentRtf,
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
    // RTF is ASCII text and would otherwise fall through to `Kind::Text`;
    // its control-word preamble is checked ahead of `looks_like_text` so
    // it gets its own kind instead of being classified as plain text.
    if data.starts_with(br"{\rtf1") {
        return Kind::DocumentRtf;
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
    fn sniffs_rtf() {
        let data = br"{\rtf1\ansi\deff0 Hello, world!}";
        assert_eq!(sniff(data), Kind::DocumentRtf);
    }

    #[test]
    fn rtf_without_version_digit_is_plain_text() {
        // `{\rtf` alone (no version number) is not a valid RTF preamble;
        // it is well-formed UTF-8 and falls through to plain text.
        assert_eq!(sniff(br"{\rtf and then some prose}"), Kind::Text);
    }

    #[test]
    fn curly_brace_text_is_not_rtf() {
        assert_eq!(sniff(b"{ just a json-looking line }"), Kind::Text);
    }
}
