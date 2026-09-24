# clean-checkout gate — row 39

date: 2026-09-24
revision under test: `file` fc666a5880ff874adae655150414b3a45832baf0 (origin/main)

## method

`file`'s only path dependency is `hemera` (`../hemera/rs`, no version pin
behind it). The owner's local `hemera` checkout carries five unpushed
commits ahead of `origin/main` (2bb9bb6 vs 23f3bbc), so per row 39's own
wording — against the default branches of its siblings, not an owner's
working tree — the check ran against a fresh detached worktree of
`hemera` at `origin/main` (23f3bbcff910ea6d504ceb505680a539260869da),
not the symlinked local tree.

## result

```
$ cargo check --tests --workspace
    Checking cyber-hemera v0.3.1 (hemera/rs @ origin/main)
    Checking cyber-file v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.23s

$ cargo test --workspace
running 4 tests
test tests::file_kind_png ... ok
test tests::hex_roundtrip ... ok
test tests::file_kind_text ... ok
test tests::same_bytes_same_particle ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`file` passes the clean-checkout gate today: no dead path, no version
pin behind `hemera`'s origin default, no crate present only in an
owner's working tree.

## remains

this closes `file`'s own slice of row 39. the row stays open until
every repo the sweep found broken has its own pin/fix PR merged; `file`
was not on the sweep's broken list and this measurement confirms why.
