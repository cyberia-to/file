//! Content-addressed files and their particle identities.
//!
//! Hemera hashes. This crate names content with [`Particle`], its 32-byte
//! digest, and carries the bytes in [`File`]. [`Kind`] and [`sniff`] identify
//! content formats for consumers such as Spark and Cyb.
//!
//! A [`File`] is a particle plus its bytes. Not every particle has data
//! on this machine; not every file has a spark that can draw it.

mod readdress;
mod sniff;

pub use readdress::{Readdressed, readdress, readdress_all};
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
}
