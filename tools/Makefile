# INFO: The Rust build tools, wrapped so the top-level Makefile and a developer
#       both have one obvious way in. Everything here is host tooling: these
#       binaries run in CI and during `make`, never on the device. The one
#       exception is zygisk-ptrace64, which is cross-compiled through the NDK by
#       loader/Makefile and is not built from here.

CARGO ?= cargo

.PHONY: build-host test-host fmt lint clean

build-host:
	$(CARGO) build --release --locked

test-host:
	$(CARGO) test --release --locked

fmt:
	$(CARGO) fmt

lint:
	$(CARGO) clippy --release --locked -- -D warnings

clean:
	$(CARGO) clean