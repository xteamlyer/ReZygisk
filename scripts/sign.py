#!/usr/bin/env python3
"""
Signing tool for VexZygisk module.

Implements module signing according to the following scheme:
  - machikado: runtime file signatures
  - misaki: whole-module signature
  - sha256: per-file SHA-256 hashes
"""

import sys
import os
import struct
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def file_sign_data(name: str, filepath: str) -> bytes:
  """
    Build the sign data block for a single file:
    name_bytes + 0x00 + 8-byte-LE-filesize + file_contents
  """

  data = bytearray()
  data.extend(name.encode('utf-8'))
  data.append(0)
  size = os.path.getsize(filepath)
  data.extend(struct.pack('<q', size))

  with open(filepath, 'rb') as f:
    while True:
      chunk = f.read(8192)
      if not chunk: break

      data.extend(chunk)

  return bytes(data)


def sign_machikado(module_dir: str, sig_name: str, private_key_bytes: bytes, public_key_bytes: bytes):
  """Sign a machikado file for the single shipped architecture."""

  root = Path(module_dir)

  # INFO: Create the list by sorting them based on their virtual/relative path,
  #         and use their virtual/relative path as the name in the signature.
  entries = []

  # INFO: The files where virtual = real. A name that this module does not
  #       ship (service.sh) is skipped rather than read, which would abort
  #       the whole build; the verifier walks the files that are there.
  for fname in ["module.prop", "rezygisk.sh", "late-load.sh", "sepolicy.rule", "post-fs-data.sh", "service.sh", "uninstall.sh"]:
    vpath = root / fname
    if not vpath.is_file():
      continue

    entries.append((str(vpath), fname, str(vpath)))

  # INFO: lib64/libzygisk.so -> lib/arm64-v8a/libzygisk.so
  vpath = root / "lib64" / "libzygisk.so"
  rpath = root / "lib" / "arm64-v8a" / "libzygisk.so"
  entries.append((str(vpath), "libzygisk.so", str(rpath)))

  # INFO: bin/zygisk-ptrace64 -> lib/arm64-v8a/libzygisk_ptrace.so
  vpath = root / "bin" / "zygisk-ptrace64"
  rpath = root / "lib" / "arm64-v8a" / "libzygisk_ptrace.so"
  entries.append((str(vpath), "zygisk-ptrace64", str(rpath)))

  # INFO: bin/zygiskd64 -> bin/arm64-v8a/zygiskd
  vpath = root / "bin" / "zygiskd64"
  rpath = root / "bin" / "arm64-v8a" / "zygiskd"
  entries.append((str(vpath), "zygiskd64", str(rpath)))

  # INFO: Sort by virtual path
  entries.sort(key=lambda e: e[0].replace("\\", "/"))

  # INFO: Accumulate all sign data. An entry whose real file is absent
  #       (service.sh) is skipped: reading it would abort the whole build.
  sign_data = bytearray()
  for _, vname, rpath in entries:
    if not Path(rpath).is_file():
      continue

    sign_data.extend(file_sign_data(vname, rpath))

  # INFO: Sign with Ed25519
  priv_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
  signature = priv_key.sign(bytes(sign_data))

  # INFO: Write signature + public key
  sig_file = root / sig_name
  with open(sig_file, 'wb') as f:
    f.write(signature)
    f.write(public_key_bytes)

  print(f"  Signed {sig_name}")


def compute_sha256_hashes(module_dir: str):
  """Compute SHA-256 hash for every file in the module directory."""

  root = Path(module_dir)
  for fpath in sorted(root.rglob('*')):
    if not fpath.is_file(): continue

    # INFO: Don't hash the sha256 files themselves
    if fpath.suffix == '.sha256': continue

    md = hashlib.sha256()
    with open(fpath, 'rb') as f:
      while True:
        chunk = f.read(4096)
        if not chunk: break

        md.update(chunk)

    hash_file = Path(str(fpath) + ".sha256")
    hash_file.write_text(md.hexdigest())

def sign_misaki(module_dir: str, private_key_bytes: bytes, public_key_bytes: bytes):
  """Sign misaki.sig for the entire module."""

  root = Path(module_dir)

  # INFO: Collect all files, sorted by path
  all_files = []
  for fpath in root.rglob('*'):
    if not fpath.is_file() or fpath.name == "misaki.sig": continue

    all_files.append(fpath)

  all_files.sort(key=lambda f: str(f).replace("\\", "/"))

  # INFO: Accumulate sign data
  sign_data = bytearray()
  for fpath in all_files:
    sign_data.extend(file_sign_data(fpath.name, str(fpath)))

  priv_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
  signature = priv_key.sign(bytes(sign_data))

  sig_file = root / "misaki.sig"
  with open(sig_file, 'wb') as f:
    f.write(signature)
    f.write(public_key_bytes)

  print("  Signed misaki.sig")

def usage():
  print("Usage: sign.py <module_dir> <private_key> <public_key>")
  print("       sign.py --no-sign <module_dir>")

def main():
  if len(sys.argv) < 3:
    usage()

    sys.exit(1)

  if sys.argv[1] == "--no-sign":
    module_dir = sys.argv[2]
    root = Path(module_dir)

    print("No private_key and public_key found, this build will not be signed")

    # INFO: The module ships one architecture, so there is one placeholder.
    (root / "machikado.arm64").touch()

    # INFO: Compute SHA256 hashes
    compute_sha256_hashes(module_dir)

    (root / "misaki.sig").touch()

    return

  if len(sys.argv) < 4:
    usage()

    sys.exit(1)

  module_dir = sys.argv[1]
  private_key_path = sys.argv[2]
  public_key_path = sys.argv[3]

  with open(private_key_path, 'rb') as f:
    private_key_bytes = f.read()
  with open(public_key_path, 'rb') as f:
    public_key_bytes = f.read()

  print("=== Guards the peace of Machikado ===")

  # INFO: Sign the shipped machikado file
  sign_machikado(module_dir, "machikado.arm64", private_key_bytes, public_key_bytes)

  # INFO: Compute SHA256 hashes for all files (including machikado)
  compute_sha256_hashes(module_dir)

  print("===   At the kitsune's wedding   ===")

  # INFO: Sign misaki, that is excluded from sha256
  sign_misaki(module_dir, private_key_bytes, public_key_bytes)

if __name__ == '__main__':
  main()
