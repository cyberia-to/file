//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Xml,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
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
    if is_xml(data) {
        return Kind::Xml;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// An XML declaration (`<?xml`), after an optional UTF-8 BOM and leading
/// whitespace. Distinguishes XML (and by extension SVG-less XML dialects
/// such as RSS/Atom feeds, and metadata sidecars) from generic text, the
/// same split JSON already gets.
fn is_xml(data: &[u8]) -> bool {
    let without_bom = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    let trimmed = trim_leading_ascii_whitespace(without_bom);
    trimmed.starts_with(b"<?xml")
}

fn trim_leading_ascii_whitespace(data: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < data.len() && data[i].is_ascii_whitespace() {
        i += 1;
    }
    &data[i..]
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
    fn sniffs_xml_declaration() {
        assert_eq!(sniff(b"<?xml version=\"1.0\"?><root/>"), Kind::Xml);
    }

    #[test]
    fn sniffs_xml_after_leading_whitespace() {
        assert_eq!(sniff(b"\n  \t<?xml version=\"1.0\"?><root/>"), Kind::Xml);
    }

    #[test]
    fn sniffs_xml_after_utf8_bom() {
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(b"<?xml version=\"1.0\"?><root/>");
        assert_eq!(sniff(&data), Kind::Xml);
    }

    #[test]
    fn xml_like_tag_without_declaration_is_text() {
        assert_eq!(sniff(b"<root><child/></root>"), Kind::Text);
    }

    #[test]
    fn near_miss_xml_prefix_is_text() {
        assert_eq!(sniff(b"<?xm not quite"), Kind::Text);
    }
}
