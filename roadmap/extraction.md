---
title: Extract shared file behavior
tags: file, roadmap, storage
status: planned
---
# Extract shared file behavior

Move reusable file behavior into `cyber-file` and make existing consumers call
it. [The specs](../specs/) are the implementation target. This page
tracks removal obligations; runtime work remains planned.

Source snapshots: [File](https://github.com/cyberia-to/file/tree/fc666a5880ff874adae655150414b3a45832baf0),
[Cybergraph](https://github.com/cyberia-to/cybergraph/tree/1571ed98a7299d513091631100e71c37178773b1),
[Radio](https://github.com/cyberia-to/radio/tree/a2fda22560b1c00bee231146808bac2600c06c8d).
The latter two are extraction branches; reconcile their current tips before a
move. Use existing tests and pending File PRs as inputs, preserving their authorship.

| Move from | Destination | Remove when |
|---|---|---|
| Radio `files.rs::hash_reader` | File streaming | Import and CLI call it |
| Cybergraph `BlobVerifier`, `blob_profile` | File verifier | Storage adapter delegates |
| Cybergraph `FileReader` | File generic reader | Only the storage port remains |
| Consumer particle parsers | File `Particle` | Only wire conversion remains |

The full source paths are Radio `radio-cli/src/files.rs` and Cybergraph
`src/files.rs`. Keep BBG `ContentStore` responsible for staging, coverage, seal,
retention and physical bytes. Keep Cybergraph `Files` as the content adapter and
application-publication bridge, called through an authorized host service.
Its BBG verifier adapter delegates to File's single implementation.

Existing `[u8; 32]` graph/wire fields may convert to `Particle` at boundaries
without rewriting stored bytes. Thin forwarding re-exports may ease a single
consumer cutover, with a named removal step. Copying the old implementation
behind the new interface leaves the move incomplete.

The same cutover removes the source implementation and ports its meaningful
tests. Run File's unit tests, consumer compilation and the streaming acceptance
cases; inspect dependency direction for cycles and unwanted DB/network crates.
Evidence belongs in `audit/extraction/` with exact commands and revisions.

Radio's file/name commands move to the Cyb filesystem adapter under
[[fs/roadmap/extraction]]. Transport diagnostics stay in Radio. Its legacy
BAO/stores require verified import and consumer parity before deletion; moving
them wholesale into File would violate File's ownership.
