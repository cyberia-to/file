//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageSvg,
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
    if looks_like_svg(data) {
        return Kind::ImageSvg;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// An SVG has no magic bytes: it is XML whose root element is `<svg`,
/// possibly behind a BOM, an `<?xml ... ?>` declaration, comments and a
/// doctype. This walks past those the same way a browser sniffer does,
/// instead of just searching the buffer for the substring anywhere.
fn looks_like_svg(data: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(data) else {
        return false;
    };
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();
    if rest.starts_with("<?xml") {
        let Some(end) = rest.find("?>") else {
            return false;
        };
        rest = rest[end + 2..].trim_start();
    }
    loop {
        if rest.starts_with("<!--") {
            let Some(end) = rest.find("-->") else {
                return false;
            };
            rest = rest[end + 3..].trim_start();
            continue;
        }
        if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("<!doctype") {
            let Some(end) = rest.find('>') else {
                return false;
            };
            rest = rest[end + 1..].trim_start();
            continue;
        }
        break;
    }
    rest.len() >= 4 && rest[..4].eq_ignore_ascii_case("<svg")
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
    fn sniffs_bare_svg() {
        assert_eq!(sniff(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), Kind::ImageSvg);
    }

    #[test]
    fn sniffs_svg_behind_xml_declaration() {
        let data = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg></svg>";
        assert_eq!(sniff(data), Kind::ImageSvg);
    }

    #[test]
    fn sniffs_svg_behind_doctype_and_comment() {
        let data = b"<?xml version=\"1.0\"?>\n<!-- generated -->\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg></svg>";
        assert_eq!(sniff(data), Kind::ImageSvg);
    }

    #[test]
    fn sniffs_svg_behind_bom() {
        let mut data = "\u{feff}".as_bytes().to_vec();
        data.extend_from_slice(b"<svg></svg>");
        assert_eq!(sniff(&data), Kind::ImageSvg);
    }

    #[test]
    fn svg_tag_is_case_insensitive() {
        assert_eq!(sniff(b"<SVG></SVG>"), Kind::ImageSvg);
    }

    #[test]
    fn xml_without_svg_root_is_not_svg() {
        let data = b"<?xml version=\"1.0\"?>\n<root><svg>not the root</svg></root>";
        assert_ne!(sniff(data), Kind::ImageSvg);
    }

    #[test]
    fn plain_text_mentioning_svg_is_not_svg() {
        assert_eq!(sniff(b"please attach an <svg> file to this email"), Kind::Text);
    }

    #[test]
    fn truncated_xml_declaration_is_not_svg() {
        assert_ne!(sniff(b"<?xml version=\"1.0\""), Kind::ImageSvg);
    }
}
