# INFO: The Rust build tools, wrapped so the top-level Makefile and a developer
#       both have one obvious way in. Everything here is host tooling: these
#       binaries run in CI and during `make`, never on the device. The two
#       exceptions are the device-side bins - zygisk-ptrace64 and the pair of
#       size probes - which carry a `required-features` marker so they are not
#       built from here at all. They are compiled for the NDK target by
#       device-target.sh, which is also where the sizes are reported.

CARGO ?= cargo

.PHONY: build-host test-host device-target fmt lint clean

build-host:
	$(CARGO) build --release --locked

test-host:
	$(CARGO) test --release --locked

# INFO: The Android target, which needs ANDROID_HOME and the NDK. Separate from
#       the two above because it is the only one that crosses a toolchain.
device-target:
	bash device-target.sh

fmt:
	$(CARGO) fmt

lint:
	$(CARGO) clippy --release --locked -- -D warnings

clean:
	$(CARGO) clean