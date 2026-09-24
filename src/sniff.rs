//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    Zip,
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
    if is_zip(data) {
        return Kind::Zip;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A ZIP local-file-header, empty-archive or spanned-archive signature.
/// The container docx/xlsx/pptx/epub/jar all share; `sniff` does not look
/// inside for those more specific formats.
fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && (data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || data.starts_with(&[0x50, 0x4b, 0x05, 0x06])
            || data.starts_with(&[0x50, 0x4b, 0x07, 0x08]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_zip_local_file_header() {
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::Zip);
    }

    #[test]
    fn sniffs_empty_zip_archive() {
        assert_eq!(sniff(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]), Kind::Zip);
    }

    #[test]
    fn sniffs_spanned_zip_archive() {
        assert_eq!(sniff(&[0x50, 0x4b, 0x07, 0x08, 0, 0, 0, 0]), Kind::Zip);
    }

    #[test]
    fn truncated_zip_signature_is_not_zip() {
        assert!(!is_zip(&[0x50, 0x4b, 0x03]));
    }

    #[test]
    fn pk_prefixed_text_is_not_zip() {
        assert_eq!(sniff(b"PKthis is just some text"), Kind::Text);
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
