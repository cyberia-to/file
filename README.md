# file

Content-addressed files and their particle identities.

A **file** is `particle + data`. Its **particle** is the 32-byte Hemera digest
that identifies the content. A particle can be known without its bytes being
available on this machine.

Rust package: `cyber-file`; library: `file`. It provides `File`, `Particle`,
`Kind` and `sniff` for Spark and Cyb. Hemera owns hashing; Spark owns opening
and rendering a file's content.

```text
hemera  →  file::{Particle, File, Kind}  →  spark
```
