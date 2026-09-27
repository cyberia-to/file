---
title: File
tags: file, soft3
crystal-type: component
crystal-domain: cyber
---
# File

The shared representation of a [[file]]: data together with its [[particle]],
the immutable 32-byte Hemera identity. The same file can have many names and
appear in many views; [[fs]] manages that organization.

File gives applications one place to construct, identify and inspect content.
[[hemera]] supplies hashing. [[spark]] opens and renders detected formats.
[[cybergraph]] supplies authorized access to bytes stored in [[bbg]].

Rust package `cyber-file`, library `file`, currently provides `File`, `Particle`,
`Kind` and `sniff`. The next step transfers streaming verification and readers
from existing consumers into this library.

[Specification](specs/README.md) · [Extraction plan](roadmap/extraction.md)
