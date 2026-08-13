#!/usr/bin/env python3
"""Scan pom.xml files for Lightwell remediable dependencies. Does not edit files."""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REQUIRED_REMEDIATION_KEYS = {
    "groupId",
    "artifactId",
    "fromVersion",
    "toVersion",
}


def _local_tag(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _child_text(parent: ET.Element, name: str) -> str | None:
    for child in parent:
        if _local_tag(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def load_catalog(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    remediations = data.get("remediations", [])
    if not isinstance(remediations, list):
        raise ValueError("catalog.remediations must be a list")
    for i, rem in enumerate(remediations):
        if not isinstance(rem, dict):
            raise ValueError(f"catalog.remediations[{i}] must be an object")
        missing = REQUIRED_REMEDIATION_KEYS - set(rem)
        if missing:
            raise ValueError(
                f"catalog.remediations[{i}] missing keys: {sorted(missing)}"
            )
        for key in REQUIRED_REMEDIATION_KEYS:
            if not str(rem.get(key, "")).strip():
                raise ValueError(f"catalog.remediations[{i}].{key} must be non-empty")
    return remediations


# Tooling / recipe modules in this demo repo are not customer app targets.
DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git",
    "target",
    "node_modules",
    "custom-recipes",
    "lightwell-recipes",
    "lightwell-github",
}


def find_poms(root: Path, exclude_dirs: set[str]) -> list[Path]:
    return sorted(
        p
        for p in root.rglob("pom.xml")
        if not any(part in exclude_dirs for part in p.parts)
    )


def _read_properties(root: ET.Element) -> dict[str, str]:
    """Read project <properties> (single-level; no parent POM inheritance)."""
    props: dict[str, str] = {}
    for elem in root:
        if _local_tag(elem.tag) != "properties":
            continue
        for child in elem:
            name = _local_tag(child.tag)
            value = (child.text or "").strip()
            if name and value:
                props[name] = value
    return props


def _resolve_version(
    raw: str, props: dict[str, str]
) -> tuple[str | None, str | None]:
    """Return (resolved_version, property_name_or_None)."""
    if raw.startswith("${") and raw.endswith("}"):
        key = raw[2:-1].strip()
        if key in props:
            return props[key], key
        return None, key
    return raw, None


def parse_dependencies(pom_text: str, *, pom_label: str = "pom.xml") -> list[dict[str, str]]:
    """Parse <dependency> entries via XML. Resolves ${property} from same POM."""
    try:
        root = ET.fromstring(pom_text)
    except ET.ParseError as exc:
        print(f"Skipping invalid XML ({pom_label}): {exc}", file=sys.stderr)
        return []

    props = _read_properties(root)
    parent_map = {c: p for p in root.iter() for c in p}
    deps: list[dict[str, str]] = []
    for elem in root.iter():
        if _local_tag(elem.tag) != "dependency":
            continue
        if _under_plugin(elem, parent_map):
            continue
        group_id = _child_text(elem, "groupId")
        artifact_id = _child_text(elem, "artifactId")
        raw_version = _child_text(elem, "version")
        if not group_id or not artifact_id or not raw_version:
            continue
        version, prop_name = _resolve_version(raw_version, props)
        if version is None:
            print(
                f"Skipping unresolved property version {group_id}:{artifact_id} "
                f"{raw_version} in {pom_label}",
                file=sys.stderr,
            )
            continue
        dep: dict[str, str] = {
            "groupId": group_id,
            "artifactId": artifact_id,
            "version": version,
        }
        if prop_name:
            dep["versionProperty"] = prop_name
        deps.append(dep)
    return deps


def _under_plugin(elem: ET.Element, parent_map: dict[ET.Element, ET.Element]) -> bool:
    cur: ET.Element | None = elem
    while cur is not None:
        if _local_tag(cur.tag) in {"plugin", "plugins", "pluginManagement"}:
            return True
        cur = parent_map.get(cur)
    return False


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
        for dep in parse_dependencies(pom.read_text(encoding="utf-8"), pom_label=rel):
            key = (dep["groupId"], dep["artifactId"], dep["version"])
            rem = index.get(key)
            if not rem:
                continue
            match: dict[str, Any] = {
                "pom": rel,
                "groupId": dep["groupId"],
                "artifactId": dep["artifactId"],
                "fromVersion": dep["version"],
                "toVersion": rem["toVersion"],
                "summary": rem.get("summary", ""),
            }
            if rem.get("tier"):
                match["tier"] = rem["tier"]
            if dep.get("versionProperty"):
                match["versionProperty"] = dep["versionProperty"]
            matches.append(match)
    return matches


def render_report(matches: list[dict[str, Any]]) -> str:
    lines = [
        "# Lightwell remediations available",
        "",
        "This scan found Maven dependencies that have a matching Lightwell remediated version.",
        "",
        "The **Lightwell Remediate** workflow opens or updates a PR on the target app automatically when matches are found.",
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
        tier = f" ({m['tier']})" if m.get("tier") else ""
        lines.append(
            f"- `{m['groupId']}:{m['artifactId']}` "
            f"`{m['fromVersion']}` → `{m['toVersion']}`{tier} "
            f"in `{m['pom']}`"
        )
        if m.get("summary"):
            lines.append(f"  - {m['summary']}")
    lines.extend(["", "## Proposed pom diff", "", "```diff"])
    for m in matches:
        lines.append(f"# {m['groupId']}:{m['artifactId']} ({m['pom']})")
        lines.append(" <dependency>")
        lines.append(f"   <groupId>{m['groupId']}</groupId>")
        lines.append(f"   <artifactId>{m['artifactId']}</artifactId>")
        lines.append(f"-  <version>{m['fromVersion']}</version>")
        lines.append(f"+  <version>{m['toVersion']}</version>")
        lines.append(" </dependency>")
        lines.append("")
    lines.append("```")
    lines.extend(
        [
            "",
            "## What happens next",
            "",
            "1. The workflow pushes branch `lightwell/remediations` (bot-owned, `--force-with-lease`).",
            "2. It opens or updates a labeled PR on the target app — review and **merge** or **close**.",
            "3. The available-updates badge is published on branch `lightwell/badge` (not `main`).",
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
    try:
        catalog = load_catalog(catalog_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Invalid catalog {catalog_path}: {exc}", file=sys.stderr)
        return 1
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
