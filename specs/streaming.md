---
title: File streaming
tags: file, storage, spec
crystal-type: spec
crystal-domain: cyber
---
# File streaming

## Ports and ownership

Large files use a [descriptor](representation.md) and a reader, keeping memory
proportional to the requested buffer. The in-memory `File` remains convenient
for small values. An implementation must expose these operations:

| Operation | Result |
|---|---|
| `hash_reader(input, scratch)` | Particle and checked byte count |
| `verify_reader(descriptor, input, scratch)` | Complete verification or error |
| `supported_constructions()` | Supported IDs and proof capabilities |
| `Verifier::new(descriptor)` | Fresh verifier or unsupported construction |
| `Verifier::update(bytes)` | Advance sequential verification |
| `Verifier::finish()` | Check final length and particle |
| `ReadAt::descriptor()` | Reader's immutable descriptor |
| `ReadAt::read_at(offset, output)` | Count of bytes read at an offset |
| `FileReader::new(source, cache_budget)` | Reader with position zero |
| `FileReader::read/seek` | Standard sequential and seek interface |

`scratch` must be nonempty. Callers own and may reuse their buffers; callees
retain no borrowed bytes after return. Input adapters may block, so hosts run
blocking I/O outside async executors. The shared algorithm is synchronous;
async hosts adapt scheduling without reimplementing hashing or validation.

`ReadAt` binds one immutable descriptor for its lifetime. It returns at most
`min(output.len(), length - offset)` bytes, permits short reads, and reports
EOF at `offset == length`. Validate the offset even for an empty output;
then an empty output returns zero. `offset > length`, arithmetic overflow and
a zero-length read into a nonempty output before EOF produce an error. Missing data
returns `Unavailable` with the missing range; it cannot masquerade as EOF.

`FileReader` adapts that port to `Read + Seek`, with position initially zero.
Seek uses checked arithmetic and may position beyond EOF, as standard seekable
files do; reading there returns zero without issuing an invalid `ReadAt` call.
Negative positions fail. Successful reads advance by exactly the returned
count. Its optional cache has a configured maximum and holds only bytes from
this descriptor. A zero cache budget disables caching. The underlying adapter
protects content for the handle's lifetime. Indefinite sealed retention satisfies
this during extraction; reclamation requires an active-read lease released on drop.

Cybergraph supplies the authorized BBG reader and lease. Radio supplies transport
framing and an injected sink/source. File's generic reader has neither a
namespace policy nor knowledge of their concrete storage/network types.

## Complete verification

Hashing consumes the input sequentially to EOF and retries `Interrupted` I/O.
All other I/O failures propagate. A read failure yields no successful particle.
Every chunk size, including one byte, must match `Particle::hash` on the same
bytes. The algorithm maintains only scratch, hash state and byte count.

`verify_reader` consumes exactly the descriptor's `length` bytes and checks
for an extra byte before success. Short input, excess input and identity
mismatch are different errors. The push verifier's `update` rejects excess
bytes; `finish` consumes it and checks submitted length and particle. The push
adapter establishes source completion, such as a bounded frame followed by FIN.
After any verification error, success requires a fresh verifier. Successful
completion returns an opaque `VerifiedDescriptor` exposing the checked descriptor;
only verifier code can construct it, and deserialization cannot create evidence.

A complete verification result is tied to the descriptor and consumed bytes.
It becomes a durable seal only when BBG atomically publishes the descriptor
against an unchanged staged-data generation. BBG prevents concurrent part
replacement during verification or rejects a stale verification result. File
does not make a durability promise. Receiving a peer's "verified" flag or a
part checksum cannot construct complete verification evidence.

Restarted transfers reuse BBG's durable coverage. For this sponge construction,
final verification rereads all staged bytes in order; restarting midway through
hashing restarts the hash unless an owner-qualified hash checkpoint exists.
Storage coverage and verification progress have different meanings.

## Cancellation and errors

Callers may stop between chunks. Cancellation drops transient verification
state. Stored progress is preserved until an explicit storage cancellation;
closing Radio leaves it available for resume. Cancellation stops scheduling
further work. An in-flight storage transaction may still commit; callers inspect
its durable outcome before retry. A cancelled caller reports no unobserved
success and initiates no subsequent name publication or export.

Errors distinguish invalid descriptor/range, unsupported construction/proof,
length overflow, short/excess data, identity mismatch, unavailable range,
cancelled work and underlying I/O. Preserve an underlying error's cause while
keeping private descriptors and content out of public logs. Backpressure means
the producer waits for the consumer's buffer or write acknowledgement.

## Acceptance

The extraction gate runs the same byte fixtures through File, Cybergraph Blob,
BBG import and Radio transfer using fixtures within Blob's inline budget:
empty, binary, text and part boundaries. Separately stream files exceeding both
that budget and the working buffers. Inline graph-record limits must never
become a file-size limit. Partitions of the same bytes must yield
identical particles and no whole-file allocation on the streaming path.

Exercise invalid Unicode hex, changed content/length/construction, EOF, excess
input, short reads, interrupted reads, I/O failure, seek overflow, unavailable
parts and cancellation. Prove at the adapter boundary that writes racing
verification cannot seal altered bytes or cancellation reclaim a sealed file.
Before reclamation is enabled, additionally verify active reads across retention
release. File length uses checked representation and available storage, with
no aggregate library/file-count ceiling. Record commands and source revisions
in `audit/`; adapter checks stay with their owners.
