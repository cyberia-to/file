# file spec

Repository: `file`. Rust package: `cyber-file`; library: `file`.

- A particle is the Hemera digest of content, 32 bytes.
- `Particle::hash(bytes)` is the only constructor from content.
- `File { particle, data }` binds bytes to a particle. Rehashing is `File::from_data`.
- `sniff(data)` returns a `Kind` from magic bytes. It is not a spark and does not render.
- No Bevy. No chrome. No graph.
