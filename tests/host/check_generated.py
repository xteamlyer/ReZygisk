#!/usr/bin/env python3
"""Guards the checked-in generated sources against their generator.

jni_hooks.h is produced by loader/src/injector/gen_jni_hooks.py and then
committed, so the build never runs the generator. That leaves two ways for the
two to drift apart with nothing to catch it:

  - the generator is edited (a new JNI signature, a changed body) and the
    header is not regenerated, so the built library keeps hooking the old set;
  - the header is edited by hand and is silently overwritten the next time
    somebody does run the generator.

Regenerating into a temporary directory and comparing catches both. The
generator takes the output path as an argument, so the scratch copy never
touches the working tree.

Run in CI's host-test job; exits non-zero on the first difference.
"""

import difflib
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

# (generator, the file it produces, both relative to the repository root)
GENERATED = [
    ("loader/src/injector/gen_jni_hooks.py", "jni_hooks.h"),
]


def read_source(path):
    """Reads a generated file and normalizes its line endings.

    The tree is pinned to LF (.gitattributes), while a generator opening a file
    in text mode on Windows would write CRLF. Comparing raw bytes would then
    report a difference on a Windows checkout that is not one, so the line
    endings are normalized away and only the content is compared."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def collect(generator, produced):
    """Runs the generator into a scratch directory; returns its output, or None
    with the reason already printed."""
    with tempfile.TemporaryDirectory() as work_dir:
        fresh_path = pathlib.Path(work_dir) / produced

        result = subprocess.run(
            [sys.executable, str(REPO / generator), str(fresh_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0 or not fresh_path.is_file():
            print(f"{generator} did not produce {produced}:")
            print((result.stderr or result.stdout).strip() or f"exit code {result.returncode}")

            return None

        return read_source(fresh_path)


def main():
    failed = False

    for generator, produced in GENERATED:
        committed_path = REPO / pathlib.Path(generator).parent / produced

        committed = read_source(committed_path)
        fresh = collect(generator, produced)

        if fresh is None:
            failed = True

            continue

        if fresh == committed:
            continue

        failed = True

        print(f"{produced} does not match {generator}:")
        print("regenerate it instead of editing it by hand.")

        for line in difflib.unified_diff(
            committed.splitlines(),
            fresh.splitlines(),
            f"committed {produced}",
            "regenerated",
            lineterm="",
            n=2,
        ):
            print(line)

    if not failed:
        print(f"generated sources check ok: {len(GENERATED)} file(s) in sync")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
