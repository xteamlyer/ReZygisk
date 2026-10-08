#!/usr/bin/env python3
"""Generates the manager update channel file for one flavour.

The file is generated here rather than committed by hand so it can never
drift from the zip it points at. The release itself is still created
manually: nothing here pushes a tag, a release or a commit, so the file
travels with the release when one is cut - and it is that commit which puts
it back on main, where module.prop's updateJson reads it from.

Usage:
  make_update_json.py --tree build --output build/out/update.json \
      --pattern "VexZygisk-v*-release.zip"
"""

import argparse
import glob
import json
import os
import re
import subprocess


def git_output(args, required=True):
    """Runs git and returns its stdout, trimmed.

    INFO: A failing git used to be invisible: `describe` without a tag and
          `log` in a shallow clone both answer with empty output, and the run
          went on to write a file with an empty changelog and a silent
          fallback range. The required calls now stop it instead.
    """
    result = subprocess.run(["git"] + args, capture_output=True, text=True)
    if required and result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}")

    return result.stdout.strip()


# INFO: Lexicographic order would pick v2.1.9 over v2.1.10, so the newest
#       archive is the one with the highest versionCode.
def archive_version_code(path):
    match = re.search(r"-v[^-]+-(\d+)-[0-9a-f]+-release\.zip$", os.path.basename(path))
    if not match:
        raise SystemExit(f"cannot parse versionCode from {path}")

    return int(match.group(1))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", required=True, help="build tree holding out/<pattern> archives")
    parser.add_argument("--output", required=True, help="path of the update channel file to write")
    parser.add_argument("--pattern", required=True, help="glob of the release archives to pick from")
    args = parser.parse_args()

    archives = glob.glob(os.path.join(args.tree, "out", args.pattern))
    if not archives:
        raise SystemExit(f"no release archive found for {args.pattern}")

    archive = max(archives, key=archive_version_code)
    name = os.path.basename(archive)

    # <prefix>-<version>-<versionCode>-<commit>-release.zip
    fields = name[: -len("-release.zip")].split("-")
    version, version_code = fields[-3], fields[-2]

    # INFO: No tag yet is an expected answer, not a failure. A shallow clone is
    #       the case that has to be noticed, and it is the log below that
    #       reports it.
    previous = git_output(["describe", "--tags", "--abbrev=0"], required=False)

    revisions = f"{previous}..HEAD" if previous else "-50"
    commits = git_output(["log", "--pretty=- %s", revisions])

    head = git_output(["rev-parse", "HEAD"])

    # INFO: The zipUrl points at a release named exactly after the version;
    #       warn while it is still cheap to notice.
    tag = git_output(["rev-parse", "-q", "--verify", f"refs/tags/{version}"], required=False)

    if not tag:
        print(f"WARNING: tag {version} does not exist yet; "
              f"{os.path.basename(args.output)}'s zipUrl will 404 until it is cut")
    elif tag != head:
        print(f"WARNING: tag {version} does not point at HEAD ({tag})")

    update = {
        "version": version,
        "versionCode": int(version_code),
        "zipUrl": "https://github.com/{}/releases/download/{}/{}".format(
            os.environ["GITHUB_REPOSITORY"], version, name),
        "changelog": "VexZygisk {}\n\n{}".format(version, commits),
    }

    with open(args.output, "w") as file:
        json.dump(update, file, indent=2, ensure_ascii=False)
        file.write("\n")

    print(args.output)
    print(json.dumps(update, indent=2))


if __name__ == "__main__":
    main()
