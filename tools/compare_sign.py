#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-check the Rust signer against the Python one it replaced.

The on-device verifier checks what the signer writes, so "it compiles" proves
nothing: the Rust tool has to feed Ed25519 exactly the bytes the previous
implementation fed it. A change in the sign block, in the order the tree is
walked, or in the way an entry is named would all still compile, and all of them
would invalidate every signature ever issued.

This builds a module tree twice, signs it with each implementation, and fails
unless every artefact is byte identical.

    cargo build --release
    python compare_sign.py

After the migration lands the Python side is gone and this has nothing to
compare against - that is the point at which it has done its job. The lasting
protection is the unit test in src/bin/sign.rs, which pins the sign block's exact
bytes and the order of the entries; this script is what proves that test was
written against the right thing in the first place.

Set VEX_PY_SIGN to the old signer when it lives somewhere other than
scripts/sign.py.
"""
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RUST_SIGN = os.path.join(HERE, "target", "release", "sign.exe")
PY_SIGN = os.environ.get("VEX_PY_SIGN", os.path.join(REPO, "scripts", "sign.py"))

# The files the signer names, in a tree laid out the way a build leaves it: the
# binaries are staged under lib64/ and bin/ and copied to their install names
# under <abi>/, and the signature names the installed paths. Without the copies
# the signer skips every binary and signs only the scripts, which would make the
# comparison pass without covering the interesting part.
FILES = {
    "module.prop": b"id=rezygisk\nname=VexZygisk\nversion=v2.2.0\n",
    "rezygisk.sh": b"#!/system/bin/sh\n# late payload\n",
    "late-load.sh": b"#!/system/bin/sh\n# late\n",
    "sepolicy.rule": b"allow zygote self cap_sys_admin\n",
    "post-fs-data.sh": b"#!/system/bin/sh\n# post fs\n",
    "uninstall.sh": b"#!/system/bin/sh\nrm -rf /data/adb/rezygisk\n",
    # Deliberately absent: service.sh. The verifier walks the files that are
    # there, and reading one that does not exist would abort the build.
    "lib64/libzygisk.so": bytes(range(256)) * 40,
    "bin/zygisk-ptrace64": bytes(range(256)) * 4,
    "bin/zygiskd64": bytes(range(256)) * 8,
    "lib/arm64-v8a/libzygisk.so": bytes(range(256)) * 40,
    "lib/arm64-v8a/libzygisk_ptrace.so": bytes(range(256)) * 4,
    "bin/arm64-v8a/zygiskd": bytes(range(256)) * 8,
}

PRIVATE_KEY = bytes(range(1, 33))
PUBLIC_KEY = bytes(range(33, 65))


def build_tree(root):
    if os.path.isdir(root):
        shutil.rmtree(root)
    for rel, body in FILES.items():
        path = os.path.join(root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(body)
    return root


def digest_tree(root):
    """Every file's relative name and content hash, so a missing or extra file
    shows up as well as a changed one."""
    out = {}
    for dirpath, _, names in os.walk(root):
        for name in sorted(names):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, "rb") as handle:
                out[rel] = hashlib.sha256(handle.read()).hexdigest()
    return out


def main():
    if not os.path.isfile(RUST_SIGN):
        sys.exit("!! build the tools first: cargo build --release")
    if not os.path.isfile(PY_SIGN):
        sys.exit("!! the reference signer is gone: %s\n"
                 "   this script only serves the migration; the lasting check is\n"
                 "   the unit test in src/bin/sign.rs" % PY_SIGN)

    py_root = build_tree(os.path.join(HERE, "cmp-python"))
    rs_root = build_tree(os.path.join(HERE, "cmp-rust"))

    key_path = os.path.join(HERE, "cmp-private.key")
    pub_path = os.path.join(HERE, "cmp-public.key")
    for path, body in ((key_path, PRIVATE_KEY), (pub_path, PUBLIC_KEY)):
        with open(path, "wb") as handle:
            handle.write(body)

    py = subprocess.run([sys.executable, PY_SIGN, py_root, key_path, pub_path],
                        capture_output=True, text=True)
    rs = subprocess.run([RUST_SIGN, rs_root, key_path, pub_path],
                        capture_output=True, text=True)

    if py.returncode != 0:
        sys.exit("!! the reference signer failed:\n" + py.stdout + py.stderr)
    if rs.returncode != 0:
        sys.exit("!! the Rust signer failed:\n" + rs.stdout + rs.stderr)

    left = digest_tree(py_root)
    right = digest_tree(rs_root)
    failures = 0

    print("%-40s %-18s %s" % ("artefact", "reference", "rust"))
    for rel in sorted(set(left) | set(right)):
        a = left.get(rel)
        b = right.get(rel)

        if a is None:
            print("%-40s %-18s %s" % (rel, "MISSING", "present"))
            failures += 1
        elif b is None:
            print("%-40s %-18s %s" % (rel, "present", "MISSING"))
            failures += 1
        elif a == b:
            print("%-40s %-18s %s" % (rel, a[:16], "same"))
        else:
            print("%-40s %-18s %s   DIFFERENT" % (rel, a[:16], b[:16]))
            failures += 1

    print()
    if failures:
        sys.exit("!! %d artefact(s) differ; the two are not interchangeable"
                 % failures)

    print("every artefact is byte identical, so a release signed by either")
    print("implementation verifies against the same public key")

    for path in (key_path, pub_path):
        os.remove(path)
    for root in (py_root, rs_root):
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()