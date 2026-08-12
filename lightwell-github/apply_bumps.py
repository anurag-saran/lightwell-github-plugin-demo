#!/usr/bin/env python3
"""Apply Lightwell version bumps from matches.json into pom.xml files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def dependency_block_pattern(group_id: str, artifact_id: str) -> re.Pattern[str]:
    return re.compile(
        rf"(<dependency>\s*"
        rf"<groupId>{re.escape(group_id)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact_id)}</artifactId>\s*"
        rf"<version>)([^<]+)(</version>)",
        re.DOTALL,
    )


def apply_match(root: Path, match: dict[str, Any]) -> bool:
    pom_path = root / match["pom"]
    if not pom_path.is_file():
        print(f"Missing pom: {pom_path}", file=sys.stderr)
        return False

    text = pom_path.read_text(encoding="utf-8")
    pattern = dependency_block_pattern(match["groupId"], match["artifactId"])
    found = False

    def replacer(m: re.Match[str]) -> str:
        nonlocal found
        current = m.group(2)
        if current != match["fromVersion"]:
            return m.group(0)
        found = True
        return f"{m.group(1)}{match['toVersion']}{m.group(3)}"

    new_text, count = pattern.subn(replacer, text, count=1)
    if count == 0 or not found:
        print(
            f"No bump applied for {match['groupId']}:{match['artifactId']} "
            f"{match['fromVersion']} in {match['pom']}",
            file=sys.stderr,
        )
        return False

    pom_path.write_text(new_text, encoding="utf-8")
    print(
        f"Updated {match['pom']}: "
        f"{match['groupId']}:{match['artifactId']} "
        f"{match['fromVersion']} -> {match['toVersion']}"
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root",
    )
    parser.add_argument(
        "--matches",
        type=Path,
        default=None,
        help="Path to matches.json from scan_poms.py",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    matches_path = (
        args.matches.resolve()
        if args.matches
        else (root / "lightwell-github" / "out" / "matches.json")
    )

    if not matches_path.is_file():
        print(f"matches.json not found: {matches_path}", file=sys.stderr)
        return 1

    payload = json.loads(matches_path.read_text(encoding="utf-8"))
    matches = payload.get("matches", [])
    if not matches:
        print("No matches to apply.")
        return 0

    ok = True
    for match in matches:
        if not apply_match(root, match):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
