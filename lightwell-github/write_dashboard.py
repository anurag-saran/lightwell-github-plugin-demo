#!/usr/bin/env python3
"""Write the app priority dashboard from one matches.json per application."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import osv_cves
import remediation_priority


def _library_line(match: dict) -> str:
    return f"{match.get('artifactId')} {match.get('fromVersion')} → {match.get('toVersion')}"


def _unique_cves(matches: list[dict]) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()
    for match in matches:
        for cve in match.get("cves") or []:
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            found.append(cve)
    return found


def _join_cell(parts: list[str]) -> str:
    return "<br>".join(parts) if parts else "—"


def render_dashboard(apps: list[tuple[str, list[dict]]]) -> str:
    """Markdown page. ``apps`` is ``(owner/name, matches)`` in display order."""
    lines = [
        "# App priority",
        "",
        "Each row is one application. Priority is the Remediation Priority Engine "
        "result for that app, the same outcome the remediation pull request shows. "
        "Libraries are the Lightwell updates available now. "
        "CVEs are the ones those updates address.",
        "",
        "| App | Priority | Available libraries | CVEs addressed |",
        "|-----|----------|---------------------|----------------|",
    ]
    for repo, matches in apps:
        name = repo.split("/")[-1]
        link = f"[{name}](https://github.com/{repo})"
        priority = remediation_priority.application_priority(matches)
        if priority:
            badge = remediation_priority._shield(
                priority, remediation_priority.priority_color(priority)
            )
        else:
            badge = "—"
        libraries = [_library_line(match) for match in matches]
        cves = [osv_cves.format_cve_inline(cve) for cve in _unique_cves(matches)]
        lines.append(f"| {link} | {badge} | {_join_cell(libraries)} | {_join_cell(cves)} |")
    lines.append("")
    return "\n".join(lines)


def _load_app(spec: str) -> tuple[str, list[dict]]:
    repo, separator, path = spec.partition("=")
    if not separator or "/" not in repo:
        raise SystemExit(f"--app must be owner/name=path/to/matches.json (got: {spec})")
    matches_path = Path(path)
    payload = json.loads(matches_path.read_text(encoding="utf-8"))
    return repo, payload.get("matches", [])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--app",
        action="append",
        required=True,
        help="owner/name=path/to/matches.json. Repeat for each application.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output markdown path (dashboard.md)",
    )
    args = parser.parse_args()
    page = render_dashboard([_load_app(spec) for spec in args.app])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(page, encoding="utf-8")
    print(f"Wrote {args.out} ({len(args.app)} app(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
