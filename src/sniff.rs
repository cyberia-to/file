//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    ArchiveTar,
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
    if is_ustar(data) {
        return Kind::ArchiveTar;
    }
    if looks_like_text(data) {
        return Kind::Text;
    }
    Kind::Opaque
}

/// POSIX ustar header: the magic `ustar` sits at byte offset 257, either
/// null-terminated (plain ustar) or followed by `00` (GNU/pre-POSIX
/// tar writes `ustar  \0`, no version digits). The 512-byte block that
/// carries it must fully exist.
fn is_ustar(data: &[u8]) -> bool {
    data.len() >= 512 && &data[257..262] == b"ustar"
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

    fn ustar_block(magic: &[u8]) -> [u8; 512] {
        let mut block = [0u8; 512];
        block[257..257 + magic.len()].copy_from_slice(magic);
        block
    }

    #[test]
    fn sniffs_posix_ustar() {
        let block = ustar_block(b"ustar\0");
        assert_eq!(sniff(&block), Kind::ArchiveTar);
    }

    #[test]
    fn sniffs_gnu_ustar() {
        let block = ustar_block(b"ustar  \0");
        assert_eq!(sniff(&block), Kind::ArchiveTar);
    }

    #[test]
    fn rejects_short_block() {
        let mut block = ustar_block(b"ustar\0").to_vec();
        block.truncate(511);
        assert_eq!(sniff(&block), Kind::Opaque);
    }

    #[test]
    fn rejects_v7_tar_with_no_magic() {
        let block = [0u8; 512];
        assert_eq!(sniff(&block), Kind::Opaque);
    }

    #[test]
    fn rejects_wrong_magic() {
        let block = ustar_block(b"zstar");
        assert_eq!(sniff(&block), Kind::Opaque);
    }
}
