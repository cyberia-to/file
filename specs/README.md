# file spec

Repository: `file`. Rust package: `cyber-file`; library: `file`.

- A particle is the Hemera digest of content, 32 bytes.
- `Particle::hash(bytes)` is the only constructor from content.
- `File { particle, data }` binds bytes to a particle. Rehashing is `File::from_data`; binding a claimed particle without rehashing is `File::bind`, trusted to the caller; binding a claimed particle and checking it by rehashing is `File::verified`, `None` on mismatch. `File::verified` is the one self-authentication path every network fetch (a peer's blob, a network store's answer) should converge on instead of re-implementing the hash check.
- `sniff(data)` returns a `Kind` from magic bytes. It is not a spark and does not render.
- No Bevy. No chrome. No graph.
