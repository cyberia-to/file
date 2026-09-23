//! Content-addressed files and their particle identities.
//!
//! Hemera hashes. This crate names content with [`Particle`], its 32-byte
//! digest, and carries the bytes in [`File`]. [`Kind`] and [`sniff`] identify
//! content formats for consumers such as Spark and Cyb.
//!
//! A [`File`] is a particle plus its bytes. Not every particle has data
//! on this machine; not every file has a spark that can draw it.

mod sniff;

pub use sniff::{Kind, sniff};

/// A content-addressed particle: Hemera digest of its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Particle([u8; 32]);

impl core::fmt::Debug for Particle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Particle").field(&self.to_hex()).finish()
    }
}

impl Particle {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hash `data` with Hemera. Same bytes, same particle, every machine.
    pub fn hash(data: &[u8]) -> Self {
        let h = hemera::hash(data);
        Self(*h.as_bytes())
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            use core::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// First four bytes, for chrome and tables.
    pub fn short_hex(&self) -> String {
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            use core::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl From<[u8; 32]> for Particle {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Particle> for [u8; 32] {
    fn from(p: Particle) -> Self {
        p.0
    }
}

impl core::fmt::Display for Particle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Particle plus the bytes it names. `file = particle + data`.
#[derive(Clone, Debug)]
pub struct File {
    pub particle: Particle,
    pub data: Vec<u8>,
}

impl File {
    /// Hash the bytes and keep them. The particle *is* Hemera(data).
    pub fn from_data(data: Vec<u8>) -> Self {
        let particle = Particle::hash(&data);
        Self { particle, data }
    }

    /// Bind bytes to an already-known particle without rehashing.
    /// The caller must have verified the digest; this crate does not.
    pub fn bind(particle: Particle, data: Vec<u8>) -> Self {
        Self { particle, data }
    }

    pub fn kind(&self) -> Kind {
        sniff(&self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_bytes_same_particle() {
        let a = Particle::hash(b"hello");
        let b = Particle::hash(b"hello");
        assert_eq!(a, b);
        assert_ne!(a, Particle::hash(b"hello!"));
    }

    #[test]
    fn hex_roundtrip() {
        let p = Particle::hash(b"roundtrip");
        assert_eq!(Particle::from_hex(&p.to_hex()), Some(p));
        assert_eq!(Particle::from_hex("zz"), None);
    }

    #[test]
    fn file_kind_text() {
        let f = File::from_data(b"a line of words".to_vec());
        assert_eq!(f.kind(), Kind::Text);
        assert_eq!(f.particle, Particle::hash(b"a line of words"));
    }

    #[test]
    fn file_kind_png() {
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::ImagePng);
    }

    #[test]
    fn file_kind_jpeg() {
        let mut data = vec![0xff, 0xd8, 0xff, 0xe0];
        data.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&data), Kind::ImageJpeg);
    }

    #[test]
    fn file_kind_gif_both_versions() {
        let mut gif87 = b"GIF87a".to_vec();
        gif87.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&gif87), Kind::ImageGif);

        let mut gif89 = b"GIF89a".to_vec();
        gif89.extend_from_slice(&[0; 16]);
        assert_eq!(sniff(&gif89), Kind::ImageGif);
    }

    #[test]
    fn sniff_empty_is_opaque_not_text() {
        // looks_like_text's own empty guard must win: no bytes is not text.
        assert_eq!(sniff(&[]), Kind::Opaque);
    }

    #[test]
    fn sniff_invalid_utf8_is_opaque() {
        // Lone continuation bytes: never a valid UTF-8 string, and match
        // none of the image magic prefixes.
        let data = vec![0x80, 0x81, 0x82, 0x83, 0x84, 0x85];
        assert_eq!(sniff(&data), Kind::Opaque);
    }

    #[test]
    fn sniff_common_control_bytes_stay_text() {
        // Tab, LF, CR and ESC are explicitly allowed by looks_like_text's
        // weirdness filter, not counted against the ratio at all.
        let mut data = b"line one\tindented\nline two\r\n".to_vec();
        data.push(0x1b); // ESC, e.g. the start of an ANSI escape sequence
        data.extend_from_slice(b"[0m more text");
        assert_eq!(sniff(&data), Kind::Text);
    }

    #[test]
    fn sniff_weird_byte_ratio_below_threshold_is_text() {
        // weird * 20 < len must hold: 100 bytes, 1 weird byte (1*20=20 < 100).
        let mut data = vec![b'a'; 99];
        data.push(0x01); // a weird control byte, still valid UTF-8
        assert_eq!(sniff(&data), Kind::Text);
    }

    #[test]
    fn sniff_weird_byte_ratio_at_threshold_is_opaque() {
        // 10 bytes, 1 weird byte: weird * 20 (20) is not < len (10), so the
        // ratio check fails and the data falls through to Opaque.
        let mut data = vec![b'a'; 9];
        data.push(0x01);
        assert_eq!(sniff(&data), Kind::Opaque);
    }
}
