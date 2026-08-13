#!/usr/bin/env python3
"""Apply Lightwell version bumps from matches.json into pom.xml files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from scan_poms import parse_dependencies  # noqa: E402


def dependency_block_pattern(group_id: str, artifact_id: str, from_version: str) -> re.Pattern[str]:
    return re.compile(
        rf"(<dependency>\s*"
        rf"<groupId>{re.escape(group_id)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact_id)}</artifactId>\s*"
        rf"<version>){re.escape(from_version)}(</version>)",
        re.DOTALL,
    )


def property_pattern(prop_name: str, from_version: str) -> re.Pattern[str]:
    return re.compile(
        rf"(<{re.escape(prop_name)}>){re.escape(from_version)}(</{re.escape(prop_name)}>)"
    )


def apply_match(root: Path, match: dict[str, Any]) -> bool:
    pom_path = root / match["pom"]
    if not pom_path.is_file():
        print(f"Missing pom: {pom_path}", file=sys.stderr)
        return False

    text = pom_path.read_text(encoding="utf-8")
    deps = parse_dependencies(text, pom_label=match["pom"])
    expected = {
        "groupId": match["groupId"],
        "artifactId": match["artifactId"],
        "version": match["fromVersion"],
    }
    # Allow versionProperty extras on the parsed dep.
    found = any(
        d["groupId"] == expected["groupId"]
        and d["artifactId"] == expected["artifactId"]
        and d["version"] == expected["version"]
        for d in deps
    )
    if not found:
        print(
            f"No bump applied for {match['groupId']}:{match['artifactId']} "
            f"{match['fromVersion']} in {match['pom']}",
            file=sys.stderr,
        )
        return False

    prop = match.get("versionProperty")
    if prop:
        pattern = property_pattern(prop, match["fromVersion"])
        new_text, count = pattern.subn(
            rf"\g<1>{match['toVersion']}\g<2>", text, count=1
        )
        where = f"property {prop}"
    else:
        pattern = dependency_block_pattern(
            match["groupId"], match["artifactId"], match["fromVersion"]
        )
        new_text, count = pattern.subn(
            rf"\g<1>{match['toVersion']}\g<2>", text, count=1
        )
        where = "dependency version"

    if count != 1:
        print(
            f"Failed surgical replace ({where}) for "
            f"{match['groupId']}:{match['artifactId']} in {match['pom']}",
            file=sys.stderr,
        )
        return False

    pom_path.write_text(new_text, encoding="utf-8")
    print(
        f"Updated {match['pom']}: "
        f"{match['groupId']}:{match['artifactId']} "
        f"{match['fromVersion']} -> {match['toVersion']}"
        + (f" via ${{{prop}}}" if prop else "")
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

    # Deduplicate property bumps (shared spring.version etc.) — apply once per
    # (pom, property, from→to); still apply each unique GAV inline bump.
    seen_props: set[tuple[str, str, str, str]] = set()
    ok = True
    for match in matches:
        prop = match.get("versionProperty")
        if prop:
            key = (
                match["pom"],
                prop,
                match["fromVersion"],
                match["toVersion"],
            )
            if key in seen_props:
                print(
                    f"Skip duplicate property bump {prop} "
                    f"({match['groupId']}:{match['artifactId']})"
                )
                continue
            seen_props.add(key)
        if not apply_match(root, match):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
