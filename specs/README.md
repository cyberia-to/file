# file spec

Repository: `file`. Rust package: `cyber-file`; library: `file`.

- A particle is the Hemera digest of content, 32 bytes.
- `Particle::hash(bytes)` is the only constructor from content.
- `File { particle, data }` binds bytes to a particle. Rehashing is `File::from_data`.
- `sniff(data)` returns a `Kind` from magic bytes. It is not a spark and does not render.
- `readdress(cid, bytes)` turns one IPFS CID from the bostrom burial into a particle: `Particle::hash(bytes)` when the burial blockstore still holds the content, `Particle::hash(cid.as_bytes())` when it does not. The second case is a black hole, addressed by a cyberlink from the CID text; it sparks to the bytes' own particle the day the bytes surface. `readdress_all` preserves order and count, one output row per input CID.
- No Bevy. No chrome. No graph.
