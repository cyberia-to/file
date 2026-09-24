//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ImageHeif,
    Opaque,
}

/// ISOBMFF major brands that mark a `ftyp` box as HEIC/HEIF/AVIF, not MP4 or MOV.
const HEIF_BRANDS: [&[u8; 4]; 8] = [
    b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"mif1", b"avif",
];

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
    if is_heif(data) {
        return Kind::ImageHeif;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// A `ftyp` ISOBMFF box whose major brand names a HEIC/HEIF/AVIF still image,
/// not the MP4/MOV brands (`isom`, `mp42`, `qt  `, ...) the same container holds.
fn is_heif(data: &[u8]) -> bool {
    if data.len() < 12 || &data[4..8] != b"ftyp" {
        return false;
    }
    let brand: &[u8; 4] = match data[8..12].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    HEIF_BRANDS.contains(&brand)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0; 16]);
        data
    }

    #[test]
    fn sniffs_heic() {
        assert_eq!(sniff(&ftyp(b"heic")), Kind::ImageHeif);
    }

    #[test]
    fn sniffs_avif() {
        assert_eq!(sniff(&ftyp(b"avif")), Kind::ImageHeif);
    }

    #[test]
    fn sniffs_mif1() {
        assert_eq!(sniff(&ftyp(b"mif1")), Kind::ImageHeif);
    }

    #[test]
    fn mp4_ftyp_is_not_heif() {
        assert_eq!(sniff(&ftyp(b"isom")), Kind::Opaque);
        assert_eq!(sniff(&ftyp(b"mp42")), Kind::Opaque);
        assert_eq!(sniff(&ftyp(b"qt  ")), Kind::Opaque);
    }

    #[test]
    fn short_ftyp_is_not_heif() {
        assert!(!is_heif(b"ftyp"));
    }

    #[test]
    fn truncated_ftyp_box_is_not_heif() {
        assert!(!is_heif(b"\0\0\0\x18ftyphe"));
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
