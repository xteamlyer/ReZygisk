#!/usr/bin/env bash
# INFO: The Rust that runs on a device: does it still compile, and how much of a
#       size budget does it cost before it does anything?
#
#       Two things live here that nothing else builds.
#
#       `zygisk-ptrace64` is the Rust front end of the ptrace engine. It is
#       linked into the same shared object as the C it calls, so on its own it
#       can only be *checked* - never linked. It was added here with an
#       `android` feature that no build ever turned on, and it rotted: by the
#       time it was wired up it did not compile at all. This script is what
#       keeps that from happening again.
#
#       The two `probe-*` bins are the measurement. They are the same program
#       twice - build a string with the formatting machinery, growing an
#       allocation as it goes - with and without `std`. The difference between
#       them is what `std` costs on the device target, which is what decides
#       whether a given module can be Rust at all: the CI size budgets are
#       `libzygisk.so` 430 KiB, `libzygisk_ptrace.so` 100 KiB and `zygiskd`
#       56 KiB (tools/src/bin/ci_size_budget.rs is the authority for those
#       numbers; they are repeated here only so the log can be read in one
#       place).
#
#       Nothing here is a gate on size - the budgets belong to the shipped
#       artefacts and this question has not been decided - but a build failure
#       is a failure.
#
# Usage: bash tools/device-target.sh
#        ANDROID_HOME must point at an SDK with an NDK; NDK_VERSION overrides
#        the pin in common.mk, which is how CI hands over the toolchain it
#        resolved.
set -eu

cd "$(dirname "$0")/.."

: "${ANDROID_HOME:?set ANDROID_HOME to an Android SDK with an NDK installed}"

# INFO: NDK_VERSION comes from the environment when CI resolved it (it falls
#       back to the newest installed NDK when the pinned one is missing, and
#       says so), and from common.mk otherwise, so a workstation runs on the
#       pin without knowing about the fallback.
ndk_version="${NDK_VERSION:-$(sed -n 's/^NDK_VERSION ?= *//p' common.mk)}"
api_level="$(sed -n 's/^API_LEVEL ?= *//p' common.mk)"

toolchain="$ANDROID_HOME/ndk/$ndk_version/toolchains/llvm/prebuilt/linux-x86_64"
linker="$toolchain/bin/aarch64-linux-android${api_level}-clang"
size_tool="$toolchain/bin/llvm-size"
strip_tool="$toolchain/bin/llvm-strip"

if [ ! -x "$linker" ]; then
  echo "No NDK linker at $linker" >&2
  echo "Looked for NDK $ndk_version under $ANDROID_HOME/ndk" >&2

  exit 1
fi

echo "NDK $ndk_version, API $api_level"
echo "Linker $linker"
echo

# INFO: Idempotent and cheap once the target is in place. Without it the two
#       builds below cannot start at all.
rustup target add aarch64-linux-android

# INFO: The one setting that makes rustc cross-compile for Android. It is the
#       NDK's own driver, so everything the C side gets - the sysroot, the API
#       level, the crt objects - the Rust side gets too.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$linker"

echo
echo "== does the device-side Rust still compile =="
# INFO: `check` and not `build`: zygisk-ptrace64 calls into the C engine that is
#       only present when the two are linked into libzygisk_ptrace.so, so a
#       standalone link would fail on those symbols rather than on anything
#       worth reporting.
cargo check --manifest-path tools/Cargo.toml --release --locked \
  --target aarch64-linux-android --features android

echo
echo "== what the standard library costs on the device target =="
# INFO: `probe` alone, and the two bins named: without them this would also try
#       to link zygisk-ptrace64, which cannot be linked on its own.
cargo build --manifest-path tools/Cargo.toml --release --locked \
  --target aarch64-linux-android --features probe \
  --bin probe-std --bin probe-no-std

out="tools/target/aarch64-linux-android/release"

for bin in probe-no-std probe-std; do
  # INFO: The shipped artefacts are budgeted stripped, so the measurement is
  #       taken the same way.
  "$strip_tool" --strip-all "$out/$bin"
done

kib() {
  local bytes
  bytes="$(stat -c %s "$1")"

  echo $(( (bytes + 1023) / 1024 ))
}

no_std_kib="$(kib "$out/probe-no-std")"
with_std_kib="$(kib "$out/probe-std")"

echo
echo "  probe-no-std   ${no_std_kib} KiB   no std, allocator over bionic malloc"
echo "  probe-std      ${with_std_kib} KiB   the same work, linked against std"
echo "  difference     $(( with_std_kib - no_std_kib )) KiB   what std costs before any of the program exists"
echo
echo "  budgets to compare against: zygiskd 56 KiB, libzygisk_ptrace.so 100 KiB, libzygisk.so 430 KiB"
echo "  measured under the crate's release profile: opt-level=s, lto, codegen-units=1, panic=abort, stripped"
echo "  (the loader builds with -Oz, so a floor measured here is the pessimistic end of the range)"
