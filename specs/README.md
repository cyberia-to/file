---
title: File specification
tags: file, spec
crystal-type: spec
crystal-domain: cyber
---
# File specification

File supplies the shared representation, format detection and verification of
one [[file]]. A [[particle]] identifies its data; [[fs]] assigns names and
organizes versions. [[hemera]] implements the hash and commitment algorithms.

These contracts specify the extraction target. Implementation status and code
to move are tracked in [the migration plan](../roadmap/extraction.md).

| Contract | Defines |
|---|---|
| [Representation](representation.md) | File, Particle, descriptor, verified data, Kind |
| [Streaming](streaming.md) | Bounded readers, hashing, verification, errors |

Rust package: `cyber-file`; library: `file`. The core depends on Hemera and
standard byte/I/O types. Adapters to BBG, Cybergraph, Radio and rendering live
with their consumers. File accepts bytes or an injected reader; opening a
database, connection or native path belongs to the host.

The extraction preserves exact-byte sponge identities. The cross-component
[canonical identity decision](https://github.com/cyberia-to/soft3/blob/189c8aa9809aed18417023c9b2f8b324dabd5b5b/roadmap/storage/identity.md)
owns the eventual structural construction and authenticated range proofs.
Changing that construction requires an explicit migration with shared vectors.
Moving Rust modules preserves existing identities.
