//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    DocumentLegacyOffice,
    Opaque,
}

/// Compound File Binary Format signature: pre-2007 Office (.doc/.xls/.ppt),
/// plus .msi and .msg, all share this one container magic. Distinguishing
/// the document type needs a walk of the OLE directory stream's root CLSID,
/// which this sniff does not attempt — same shape as file#22's ZIP-then-
/// subtype split for docx/xlsx/pptx/epub.
const CFB_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

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
    if data.starts_with(&CFB_MAGIC) {
        return Kind::DocumentLegacyOffice;
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
    fn sniffs_cfb() {
        let mut data = CFB_MAGIC.to_vec();
        data.extend_from_slice(&[0; 24]);
        assert_eq!(sniff(&data), Kind::DocumentLegacyOffice);
    }

    #[test]
    fn short_cfb_prefix_is_not_cfb() {
        assert_eq!(sniff(&CFB_MAGIC[..4]), Kind::Opaque);
    }

    #[test]
    fn near_miss_cfb_magic_is_not_cfb() {
        let mut wrong = CFB_MAGIC;
        wrong[7] = 0xe2;
        assert_eq!(sniff(&wrong), Kind::Opaque);
    }
}
