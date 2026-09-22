//! Re-addressing the bostrom burial graph under Hemera.
//!
//! Every bostrom particle was an IPFS CID. The migrated graph names it by
//! [`Particle::hash`] of its bytes instead. A CID with bytes present in the
//! burial blockstore gets the particle of those bytes; the CID becomes a
//! naming cyberlink onto it. A CID whose bytes never surfaced gets the
//! particle of the CID label itself: a black hole, addressed by a cyberlink
//! from the CID text, sparked if the bytes ever arrive.
//!
//! Two things here are provisional and follow decisions that are open on
//! cyber/launch.md, not settled by this module:
//!
//! - the particle of present bytes is whatever [`Particle::hash`] computes
//!   today: `hemera::hash(data)`, 32 bytes, no prefix. row 19 (one particle
//!   definition) may move it to hemera over the lens commitment; when it
//!   does, this module follows the crate and every re-addressed particle
//!   changes with it.
//! - the identity of a black hole is `Particle::hash` of the CID text. the
//!   missing-bytes decision may replace it; one reason it is open is that
//!   this value coincides with the particle of a file whose bytes are
//!   exactly that CID text, so a black hole and such a file would share one
//!   node.
//!
//! What does not move: the CID is kept on every row, as a name for the
//! naming cyberlink, never as the identity.

use crate::Particle;

/// One re-addressed entry: the old IPFS CID and its new particle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readdressed {
    pub cid: String,
    pub particle: Particle,
    pub has_bytes: bool,
}

/// Re-address one CID. `bytes` is `Some` when the burial blockstore still
/// holds the content; `None` marks a black hole.
pub fn readdress(cid: &str, bytes: Option<&[u8]>) -> Readdressed {
    let (particle, has_bytes) = match bytes {
        Some(data) => (Particle::hash(data), true),
        None => (Particle::hash(cid.as_bytes()), false),
    };
    Readdressed { cid: cid.to_string(), particle, has_bytes }
}

/// Re-address a batch. One output row per input CID, same order: the count
/// of the run is the count of the manifest, by construction.
pub fn readdress_all<'a>(
    entries: impl Iterator<Item = (&'a str, Option<&'a [u8]>)>,
) -> Vec<Readdressed> {
    entries.map(|(cid, bytes)| readdress(cid, bytes)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_present_hashes_the_bytes() {
        let r = readdress("QmExample", Some(b"file contents"));
        assert!(r.has_bytes);
        assert_eq!(r.particle, Particle::hash(b"file contents"));
    }

    #[test]
    fn missing_bytes_is_a_black_hole_on_the_cid_label() {
        let r = readdress("QmMissing", None);
        assert!(!r.has_bytes);
        assert_eq!(r.particle, Particle::hash(b"QmMissing"));
    }

    #[test]
    fn black_holes_of_different_cids_differ() {
        let a = readdress("QmA", None);
        let b = readdress("QmB", None);
        assert_ne!(a.particle, b.particle);
    }

    #[test]
    fn black_hole_sparks_to_the_bytes_particle_once_they_surface() {
        let cid = "QmSparked";
        let dark = readdress(cid, None);
        let lit = readdress(cid, Some(b"the bytes surfaced"));
        assert_ne!(dark.particle, lit.particle);
        assert_eq!(lit.particle, Particle::hash(b"the bytes surfaced"));
    }

    #[test]
    fn cid_is_kept_on_every_row_as_the_name() {
        let lit = readdress("QmLit", Some(b"bytes"));
        let dark = readdress("QmDark", None);
        assert_eq!(lit.cid, "QmLit");
        assert_eq!(dark.cid, "QmDark");
    }

    #[test]
    fn count_matches_the_manifest() {
        let cids = ["QmOne", "QmTwo", "QmThree"];
        let bytes: [Option<&[u8]>; 3] = [Some(b"one"), None, Some(b"three")];
        let out = readdress_all(cids.into_iter().zip(bytes));
        assert_eq!(out.len(), cids.len());
        assert!(out[1].has_bytes == false);
    }
}
