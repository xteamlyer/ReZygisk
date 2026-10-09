# Build tools

The packaging and release tooling, in Rust. These binaries run on the machine
that builds the module — in CI and during `make` — and never on the device.

| Tool | What it does |
|---|---|
| `sign` | Module signing: the `machikado` runtime signature, the `misaki` whole-module signature, and the per-file SHA-256 sidecars. |
| `ci-size-budget` | Fails the build when a binary outgrows its budget. |
| `make-update-json` | Writes the manager's update channel file for one flavour. |
| `zygisk-ptrace64` | The tracer's command line front end. Built for Android only, through `loader/Makefile`. |

## Building

```sh
make -C tools build-host    # release binaries into tools/target/release
make -C tools test-host     # the unit tests
make -C tools lint          # clippy, warnings denied
```

The top-level `make` builds the signer itself, because packaging calls it.

## Why the tracer CLI is separate

`zygisk-ptrace64` owns the subcommand grammar — the banner, the usage text, and
in particular the validation of the pid in `trace`, which has to be rejected
before it reaches `kill()` or it signals the whole process group.

Everything a subcommand *does* is still C: `init_monitor`, `trace_zygote`,
`send_control_command`, `rezygiskd_get_info` and the mount revert live in
`loader/src/ptracer/` and `loader/src/injector/`, and they are linked into the
same shared object. That split is deliberate. The engine is ptrace, `/proc`
parsing and socket code with no CLI in it, and moving it is a different job with
a different risk profile — one that also has to answer for this project's
primary requirement, which is leaving nothing behind in the process it injects
into.

Because of that the crate does not build `zygisk-ptrace64` for the host: every
symbol it calls exists only in the Android build. It sits behind the `android`
feature, off by default, so `cargo test` works on a workstation.

## Dependencies

Two, and both are what the Python scripts needed from outside the standard
library:

- `sha2` — the per-file hashes.
- `ed25519-compact` — the signatures, in pure Rust with no OpenSSL behind it.

## The signature has to stay byte-compatible

The on-device verifier checks these signatures, so a signer that merely compiles
is not good enough: it has to feed Ed25519 exactly the bytes the previous
implementation fed it. The block is `name`, a NUL, the file size as a
little-endian `i64`, then the contents — reproduced rather than tidied up, and
pinned by the tests in `src/bin/sign.rs`.

The migration was verified against the implementation it replaced by signing a
module tree with both and comparing every artefact; that comparison tool went
with the Python signer, since it has nothing left to compare against. What
remains is the unit tests in `src/bin/sign.rs`, which is what makes the property
checkable at all: they pin the sign block's exact bytes and the walk order, so a
change no compiler would catch still fails the build.
