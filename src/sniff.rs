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
    Docx,
    Xlsx,
    Pptx,
    Epub,
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
        return sniff_zip_container(data);
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A ZIP local-file-header, empty-archive or spanned-archive signature.
fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && (data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || data.starts_with(&[0x50, 0x4b, 0x05, 0x06])
            || data.starts_with(&[0x50, 0x4b, 0x07, 0x08]))
}

/// docx/xlsx/pptx/epub are ZIP archives distinguished only by the entry
/// names inside. Entry names sit in the plain (never-compressed) local
/// file header / central directory, so a literal byte search for the one
/// entry each format is defined by is enough without walking the ZIP
/// structure — a real parse belongs to whatever eventually opens these,
/// not to this magic-bytes sniff.
fn sniff_zip_container(data: &[u8]) -> Kind {
    if contains(data, b"mimetypeapplication/epub+zip") {
        Kind::Epub
    } else if contains(data, b"word/document.xml") {
        Kind::Docx
    } else if contains(data, b"xl/workbook.xml") {
        Kind::Xlsx
    } else if contains(data, b"ppt/presentation.xml") {
        Kind::Pptx
    } else {
        Kind::Zip
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
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

    fn zip_containing(entry_name: &[u8]) -> Vec<u8> {
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(entry_name);
        data
    }

    #[test]
    fn plain_zip_with_no_known_entry_is_zip() {
        assert_eq!(sniff(&zip_containing(b"readme.txt")), Kind::Zip);
    }

    #[test]
    fn epub_mimetype_entry_sniffs_as_epub() {
        assert_eq!(
            sniff(&zip_containing(b"mimetypeapplication/epub+zip")),
            Kind::Epub
        );
    }

    #[test]
    fn word_document_entry_sniffs_as_docx() {
        assert_eq!(sniff(&zip_containing(b"word/document.xml")), Kind::Docx);
    }

    #[test]
    fn workbook_entry_sniffs_as_xlsx() {
        assert_eq!(sniff(&zip_containing(b"xl/workbook.xml")), Kind::Xlsx);
    }

    #[test]
    fn presentation_entry_sniffs_as_pptx() {
        assert_eq!(sniff(&zip_containing(b"ppt/presentation.xml")), Kind::Pptx);
    }

    #[test]
    fn empty_zip_archive_is_zip() {
        assert_eq!(sniff(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]), Kind::Zip);
    }
}
