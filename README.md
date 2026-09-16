# particle

A **particle** is a 32-byte Hemera digest as a named thing. Hemera hashes; this crate *is* the hash as identity.

A **file** is `particle + data`. Not every particle has bytes on this machine.

Crate: `cyber-particle`. Downstream: bbg, nox, cyb, spark, prysm — they take `Particle`, they do not invent `[u8; 32]`.

```
hemera  →  particle  →  spark
                ↑
              file = particle + data
```
