---
title: File representation
tags: file, particle, spec
crystal-type: spec
crystal-domain: cyber
---
# File representation

## File and particle

A [[file]] is `(particle, data)`. Its [[particle]] is the immutable 32-byte
Hemera identity of that data. A known particle with unavailable data is a file
reference. A [[name]], path, author and version relationship belong to FS and
Cybergraph; they remain outside this pair.

`Particle` wraps exactly `[u8; 32]`. Equality, ordering and hashing use these
bytes. Display emits 64 lowercase ASCII hexadecimal digits. Parsing accepts
64 ASCII hexadecimal digits after trimming surrounding whitespace, accepts
either letter case, and returns failure for other inputs, including malformed
Unicode. Parsing arbitrary text must never panic. Parsing establishes an
address, while verification establishes its relationship to data.

Under the supported extraction construction:

```
Particle::hash(data) = hemera::hash(data)
```

The input is the exact byte sequence, including the empty sequence. File adds
no filename, length prefix, encoding tag, MIME type or transport framing to
that input. Partitioning bytes into storage parts or network frames preserves
the particle. Hemera owns padding, sponge parameters and output encoding.

`File::from_data(Vec<u8>)` computes that identity and binds the owned bytes.
`File::bind(particle, data)` and direct construction of the existing public
fields carry a caller's assertion. Trust boundaries must verify that assertion.

The target verified handle, `VerifiedFile`, privately owns a checked `File`.
It exposes immutable access to data and particle; mutation or taking the
underlying mutable value consumes the handle. `verify(File)` returns this
handle only after recomputing and matching the particle, otherwise
`IdentityMismatch`. A verified constructor from owned data may reuse the hash
it computed while retaining exclusive ownership of those bytes.
This handle is process-local evidence, with no serializable bypass constructor.

## Describing a large file

`Descriptor { particle, construction, length }` describes one byte sequence.
`length` is a checked `u64` byte count. The construction field selects verifier
semantics; it contributes no additional entropy or authority to the particle.
Transport and storage must agree on all three fields before exchanging parts.

For extraction, preserve the existing construction identifier:

```
hemera::hash(b"cybergraph/blob/hemera-sponge")
```

The spelling survives the module move to preserve stored descriptors and
requests. A capability query enumerates supported constructions. An unknown
identifier produces `UnsupportedConstruction` before accepting data. Network
input cannot select an unconfigured verifier or fall back to another hash.

Storage part size, upload request, namespace, local coverage and retention are
separate storage/transfer metadata. A descriptor alone proves neither its
claimed length nor possession of the file. A complete verified stream checks
both length and particle. Physical part size may differ between replicas.

The initial construction verifies complete files. Reading a range of a locally
verified immutable file is possible; a transferable proof authenticating that
range requires the separately qualified Hemera construction. Unsupported proof
requests fail explicitly. BAO roots, structural roots and polynomial commitments
retain their declared meanings during import.

## Format detection

`Kind` describes an apparent format; `sniff` examines bytes without decoding,
executing, fetching or rendering their contents. Spark owns opening/rendering.
Names and extensions can be presentation hints; they never change the particle
or override a detected signature in File.

Preserve this ordered baseline detector:

| Kind | Required prefix |
|---|---|
| ImagePng | `89 50 4e 47 0d 0a 1a 0a` |
| ImageJpeg | `ff d8 ff` |
| ImageGif | ASCII `GIF87a` or `GIF89a` |
| ImageWebp | ASCII `RIFF`, four bytes, ASCII `WEBP` |
| Text | Nonempty UTF-8 satisfying the rule below |
| Opaque | Remaining inputs, including empty data |

Text's control-byte count includes bytes below `09` or in `0e..1f`, except
`1b`. It must be strictly less than one twentieth of total bytes. Implement
the comparison without multiplication overflow. Truncated magic falls through
to subsequent rules. Detection is a hint, including for hostile/polyglot files;
the renderer validates its actual format.

For streaming, `sniff_prefix(bytes, complete)` returns
`Detection { kind: sniff(bytes), complete }`. The caller supplies `complete`
only when the bytes cover the entire file. Incomplete UTF-8 falls through to
Opaque; magic matches and the Text heuristic on a prefix remain provisional
format hints. Calling `sniff` on a prefix must not claim full-file validation.
Prefix reads consume the caller's explicit byte budget. Detector acceptance
includes truncated signatures, split UTF-8 and the exact control-byte threshold.
