#!/usr/bin/env python3
"""Scan pom.xml files for Lightwell remediable dependencies. Does not edit files."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

import osv_cves

REQUIRED_REMEDIATION_KEYS = {
    "groupId",
    "artifactId",
    "fromVersion",
    "toVersion",
}

MATCH_DROP_IN = "drop_in"
MATCH_SERVICED_OTHER = "serviced_other_version"

MEANING_DROP_IN = "Swap the version suffix. No code change."
MEANING_SERVICED_OTHER = (
    "Move to a serviced version, or request your version."
)

_RH_SUFFIX_RE = re.compile(r"[.-](redhat|rhlw)-\d+$", re.I)


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


def base_version(version: str) -> str:
    """Strip Lightwell / Red Hat rebuild suffix (``…rhlw-NNNN`` / ``…redhat-NNNN``)."""
    return _RH_SUFFIX_RE.sub("", version or "")


def _should_apply(match: dict[str, Any]) -> bool:
    """Drop-in rebuilds are auto-applied; other-version upgrades are table-only."""
    if match.get("apply") is False:
        return False
    return match.get("matchKind", MATCH_DROP_IN) == MATCH_DROP_IN


def _best_remediation(candidates: list[dict[str, str]]) -> dict[str, str]:
    return max(candidates, key=lambda r: osv_cves.version_key(r["toVersion"]))


def _build_match(
    *,
    pom: str,
    dep: dict[str, str],
    rem: dict[str, str],
    match_kind: str,
    serviced_versions: list[str] | None = None,
    meaning: str,
) -> dict[str, Any]:
    match: dict[str, Any] = {
        "pom": pom,
        "groupId": dep["groupId"],
        "artifactId": dep["artifactId"],
        "fromVersion": dep["version"],
        "toVersion": rem["toVersion"],
        "summary": rem.get("summary", ""),
        "matchKind": match_kind,
        "meaning": meaning,
        "apply": match_kind == MATCH_DROP_IN,
    }
    if rem.get("tier"):
        match["tier"] = rem["tier"]
    if dep.get("versionProperty"):
        match["versionProperty"] = dep["versionProperty"]
    if serviced_versions:
        match["servicedVersions"] = serviced_versions
    else:
        match["servicedVersions"] = [rem["toVersion"]]
    return match


def match_remediations(
    root: Path,
    catalog: list[dict[str, str]],
    exclude_dirs: set[str],
) -> list[dict[str, Any]]:
    """Match POM deps to catalog drop-ins and newer serviced versions.

    * **drop_in** — Red Hat rebuilt the exact upstream version you run (auto-applied).
    * **serviced_other_version** — catalog only has a newer/other base (table-only;
      not written into the pom by ``apply_bumps``).
    """
    exact_index = {
        (r["groupId"], r["artifactId"], r["fromVersion"]): r for r in catalog
    }
    by_ga: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for rem in catalog:
        by_ga[(rem["groupId"], rem["artifactId"])].append(rem)

    matches: list[dict[str, Any]] = []
    for pom in find_poms(root, exclude_dirs):
        rel = pom.relative_to(root).as_posix()
        for dep in parse_dependencies(pom.read_text(encoding="utf-8"), pom_label=rel):
            g, a, v = dep["groupId"], dep["artifactId"], dep["version"]
            rem = exact_index.get((g, a, v))
            if rem:
                matches.append(
                    _build_match(
                        pom=rel,
                        dep=dep,
                        rem=rem,
                        match_kind=MATCH_DROP_IN,
                        meaning=MEANING_DROP_IN,
                    )
                )
                continue

            run_base = base_version(v)
            run_key = osv_cves.version_key(run_base)
            same_base = [
                r
                for r in by_ga.get((g, a), [])
                if r["fromVersion"] == run_base
            ]
            if same_base and osv_cves.is_remediated_version(v):
                best = _best_remediation(same_base)
                if osv_cves.version_key(best["toVersion"]) > osv_cves.version_key(v):
                    matches.append(
                        _build_match(
                            pom=rel,
                            dep=dep,
                            rem=best,
                            match_kind=MATCH_DROP_IN,
                            meaning=MEANING_DROP_IN,
                        )
                    )
                continue

            forward = [
                r
                for r in by_ga.get((g, a), [])
                if osv_cves.version_key(r["fromVersion"]) > run_key
            ]
            if not forward:
                continue
            best = _best_remediation(forward)
            serviced = sorted(
                {r["toVersion"] for r in forward},
                key=osv_cves.version_key,
            )
            matches.append(
                _build_match(
                    pom=rel,
                    dep=dep,
                    rem=best,
                    match_kind=MATCH_SERVICED_OTHER,
                    serviced_versions=serviced,
                    meaning=MEANING_SERVICED_OTHER,
                )
            )
    return matches


def _cve_cell(m: dict[str, Any]) -> str:
    cves = m.get("cves") or []
    if not cves:
        return "—"
    return ", ".join(osv_cves.format_cve_inline(c) for c in cves)


def _serviced_cell(m: dict[str, Any]) -> str:
    versions = m.get("servicedVersions") or [m.get("toVersion")]
    return ", ".join(f"`{v}`" for v in versions if v)


def _highest_cell(m: dict[str, Any]) -> str:
    if m.get("max_cvss") is not None:
        return f"**{m['max_cvss']}** {m.get('max_severity') or ''}".strip()
    return "—"


def render_report(matches: list[dict[str, Any]]) -> str:
    lines = [
        "# Lightwell remediations available",
        "",
        "This scan found Maven dependencies that have a matching Lightwell remediated version.",
        "",
        "CVE IDs and CVSS scores come from Lightwell OSV advisories for the target `.rhlw` / `.redhat` build.",
        "Empty CVE cells mean no advisory claims that build as a fix (common for some validated drop-ins).",
        "",
        "**Drop-in** rows are proposed as pom edits. **Serviced — at a different version** rows "
        "are informational only in this table (a real upgrade, or a request for your exact version).",
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

    lines.extend(
        [
            "## Proposed bumps",
            "",
            "| Dependency | You run | Serviced versions | What it means for you | CVEs fixed (CVSS) | Highest |",
            "|------------|---------|-------------------|-----------------------|-------------------|---------|",
        ]
    )
    for m in matches:
        lib = f"`{m['groupId']}:{m['artifactId']}`"
        you_run = f"`{m['fromVersion']}`"
        meaning = m.get("meaning") or MEANING_DROP_IN
        if m.get("matchKind") == MATCH_SERVICED_OTHER:
            meaning = f"**Serviced — at a different version.** {MEANING_SERVICED_OTHER}"
        elif m.get("tier"):
            meaning = f"{meaning} ({m['tier']})"
        lines.append(
            f"| {lib} | {you_run} | {_serviced_cell(m)} | {meaning} | "
            f"{_cve_cell(m)} | {_highest_cell(m)} |"
        )

    apply_matches = [m for m in matches if _should_apply(m)]

    lines.extend(["", "### Details", ""])
    if not apply_matches:
        lines.append(
            "No drop-in pom edits. See **Serviced — at a different version** rows "
            "in the Proposed bumps table above."
        )
        lines.append("")
    for m in apply_matches:
        tier = f" ({m['tier']})" if m.get("tier") else ""
        lines.append(
            f"- `{m['groupId']}:{m['artifactId']}` "
            f"`{m['fromVersion']}` → `{m['toVersion']}`{tier} "
            f"in `{m['pom']}`"
        )
        if m.get("summary"):
            lines.append(f"  - {m['summary']}")
        cves = m.get("cves") or []
        if cves:
            lines.append("  - **CVEs fixed:**")
            for c in cves:
                sev = ""
                if c.get("cvss") is not None:
                    sev = f" — CVSS {c['cvss']} ({c.get('severity') or '?'})"
                lines.append(
                    f"    - [`{c['id']}`](https://nvd.nist.gov/vuln/detail/{c['id']}){sev}"
                )
                if c.get("summary"):
                    lines.append(f"      - {c['summary']}")
        else:
            lines.append(
                "  - CVEs fixed: *(none listed in Lightwell OSV for this build)*"
            )

    lines.extend(["", "## Proposed pom diff", "", "```diff"])
    if not apply_matches:
        lines.append("# (no drop-in pom edits; see serviced-other rows in the table above)")
        lines.append("")
    for m in apply_matches:
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
    parser.add_argument(
        "--osv-dir",
        type=Path,
        default=None,
        help="Local directory of Lightwell OSV JSON advisories (offline / tests)",
    )
    parser.add_argument(
        "--osv-url",
        default=osv_cves.DEFAULT_OSV_URL,
        help="Lightwell OSV remediated index URL (default: public demo feed)",
    )
    parser.add_argument(
        "--no-osv",
        action="store_true",
        help="Skip CVE/CVSS enrichment (catalog match only)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not fetch OSV over the network (use --osv-dir only)",
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

    if not args.no_osv:
        osv_dir = args.osv_dir.resolve() if args.osv_dir else None
        fetch = not args.offline
        records = osv_cves.load_osv_index(
            osv_dir=osv_dir,
            osv_url=args.osv_url if fetch else None,
            fetch=fetch,
        )
        if records:
            print(f"Loaded {len(records)} Lightwell OSV advisory(ies) for CVE join")
        else:
            print("No OSV advisories loaded — matches will have empty CVE lists")
        before = {id(m): m.get("toVersion") for m in matches}
        osv_cves.attach_cves_to_matches(matches, records)
        elevated = sum(
            1 for m in matches if m.get("toVersion") != before.get(id(m))
        )
        if elevated:
            print(
                f"Elevated {elevated} match(es) to highest OSV .rhlw fixed build"
            )
    else:
        for m in matches:
            m.setdefault("cves", [])
            m.setdefault("max_cvss", None)
            m.setdefault("max_severity", None)

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
