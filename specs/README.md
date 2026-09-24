# file spec

Repository: `file`. Rust package: `cyber-file`; library: `file`.

- A particle is the Hemera digest of content, 32 bytes.
- `Particle::hash(bytes)` is the only constructor from content.
- `File { particle, data }` binds bytes to a particle. Rehashing is `File::from_data`.
- `sniff(data)` returns a `Kind` from magic bytes. It is not a spark and does not render.
- `Kind` covers text, PNG/JPEG/GIF/WebP images and WAV/MP3 audio by magic bytes; unrecognized bytes are `Kind::Opaque`.
- No Bevy. No chrome. No graph.
