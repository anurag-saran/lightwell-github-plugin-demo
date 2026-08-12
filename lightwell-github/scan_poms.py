#!/usr/bin/env python3
"""Scan pom.xml files for Lightwell remediable dependencies. Does not edit files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

DEPENDENCY_RE = re.compile(
    r"<dependency>\s*"
    r"<groupId>(?P<groupId>[^<]+)</groupId>\s*"
    r"<artifactId>(?P<artifactId>[^<]+)</artifactId>\s*"
    r"(?:<version>(?P<version>[^<]+)</version>)?",
    re.DOTALL,
)


def load_catalog(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("remediations", [])


# Tooling / recipe modules in this demo repo are not customer app targets.
DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git",
    "target",
    "node_modules",
    "custom-recipes",
    "lightwell-recipes",
    "lightwell-github",
    "_lightwell",
}


def find_poms(root: Path, exclude_dirs: set[str]) -> list[Path]:
    return sorted(
        p
        for p in root.rglob("pom.xml")
        if not any(part in exclude_dirs for part in p.parts)
    )


def parse_dependencies(pom_text: str) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    for match in DEPENDENCY_RE.finditer(pom_text):
        version = (match.group("version") or "").strip()
        if not version:
            continue
        deps.append(
            {
                "groupId": match.group("groupId").strip(),
                "artifactId": match.group("artifactId").strip(),
                "version": version,
            }
        )
    return deps


def match_remediations(
    root: Path,
    catalog: list[dict[str, str]],
    exclude_dirs: set[str],
) -> list[dict[str, Any]]:
    index = {
        (r["groupId"], r["artifactId"], r["fromVersion"]): r for r in catalog
    }
    matches: list[dict[str, Any]] = []
    for pom in find_poms(root, exclude_dirs):
        rel = pom.relative_to(root).as_posix()
        for dep in parse_dependencies(pom.read_text(encoding="utf-8")):
            key = (dep["groupId"], dep["artifactId"], dep["version"])
            rem = index.get(key)
            if not rem:
                continue
            matches.append(
                {
                    "pom": rel,
                    "groupId": dep["groupId"],
                    "artifactId": dep["artifactId"],
                    "fromVersion": dep["version"],
                    "toVersion": rem["toVersion"],
                    "summary": rem.get("summary", ""),
                }
            )
    return matches


def render_report(matches: list[dict[str, Any]]) -> str:
    lines = [
        "# Lightwell remediations available",
        "",
        "This scan found Maven dependencies that have a matching Lightwell remediated version.",
        "",
        "**No pull request has been opened yet.** Review the proposed changes below, then open a PR with the button.",
        "",
    ]
    if not matches:
        lines.extend(
            [
                "## Result",
                "",
                "No matching Lightwell remediations found in this repository.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(["## Proposed bumps", ""])
    for m in matches:
        lines.append(
            f"- `{m['groupId']}:{m['artifactId']}` "
            f"`{m['fromVersion']}` → `{m['toVersion']}` "
            f"in `{m['pom']}`"
        )
        if m.get("summary"):
            lines.append(f"  - {m['summary']}")
    lines.extend(["", "## Proposed pom diff", "", "```diff"])
    for m in matches:
        lines.append(f"--- a/{m['pom']}")
        lines.append(f"+++ b/{m['pom']}")
        lines.append(
            f"-            <version>{m['fromVersion']}</version>"
        )
        lines.append(
            f"+            <version>{m['toVersion']}</version>"
        )
        lines.append("")
    lines.append("```")
    lines.extend(
        [
            "",
            "## Next step (open PR)",
            "",
            "1. Open **Actions** → **Lightwell Open PR**",
            "2. Click **Run workflow**",
            "3. Set `confirm` to `open-pr`",
            "4. Run the workflow — that creates the branch and pull request",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root to scan",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help="Path to catalog.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("lightwell-github/out"),
        help="Directory for matches.json and report.md",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude (repeatable). Defaults include recipe modules.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    catalog_path = (
        args.catalog.resolve()
        if args.catalog
        else (root / "lightwell-github" / "catalog.json")
    )
    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = (root / out_dir).resolve()
    else:
        out_dir = out_dir.resolve()

    if not catalog_path.is_file():
        print(f"Catalog not found: {catalog_path}", file=sys.stderr)
        return 1

    exclude_dirs = set(DEFAULT_EXCLUDE_DIR_NAMES) | set(args.exclude_dir)
    catalog = load_catalog(catalog_path)
    matches = match_remediations(root, catalog, exclude_dirs)
    report = render_report(matches)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "matches.json").write_text(
        json.dumps({"matches": matches}, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "report.md").write_text(report + "\n", encoding="utf-8")

    print(report)
    print(f"\nWrote {out_dir / 'matches.json'} ({len(matches)} match(es))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
