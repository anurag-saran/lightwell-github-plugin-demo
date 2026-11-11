#!/usr/bin/env python3
"""Write the manager dashboard from one matches.json per application."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import osv_cves
import remediation_priority


_RANK = {"Immediate": 0, "Out-of-Cycle": 1, "Scheduled": 2, "Defer": 3}
_LEAD = {
    "Immediate": "needs a patch now",
    "Out-of-Cycle": "needs a patch before the next feature release",
    "Scheduled": "can wait for the next release",
    "Defer": "can be tracked",
}
_MEANING = {
    "Immediate": "Act now.",
    "Out-of-Cycle": "Patch before the next feature release.",
    "Scheduled": "Take it in the next release.",
    "Defer": "Track only.",
}


def _rank(priority: str | None) -> int:
    return _RANK.get(priority or "", 4)


def _ordered_apps(apps: list[tuple[str, list[dict]]]) -> list[tuple[str, list[dict]]]:
    indexed = list(enumerate(apps))
    indexed.sort(
        key=lambda item: (
            _rank(remediation_priority.application_priority(item[1][1])),
            item[0],
        )
    )
    return [item[1] for item in indexed]


def _ordered_matches(matches: list[dict]) -> list[dict]:
    indexed = list(enumerate(matches))
    indexed.sort(
        key=lambda item: (
            _rank(remediation_priority.match_priority(item[1])),
            item[0],
        )
    )
    return [item[1] for item in indexed]


def _badge(priority: str | None) -> str:
    if not priority:
        return "—"
    return remediation_priority._shield(priority, remediation_priority.priority_color(priority))


def _cve_cell(match: dict) -> str:
    parts = [
        osv_cves.format_cve_inline(cve)
        for cve in (match.get("cves") or [])
        if cve.get("id")
    ]
    return "<br>".join(parts) if parts else "—"


def _cve_count(matches: list[dict]) -> int:
    seen: set[str] = set()
    for match in matches:
        for cve in match.get("cves") or []:
            cve_id = cve.get("id")
            if cve_id:
                seen.add(cve_id)
    return len(seen)


def _count_label(count: int) -> str:
    return "1 CVE" if count == 1 else f"{count} CVEs"


def _lead(apps: list[tuple[str, list[dict]]]) -> str:
    sentences = []
    for repo, matches in apps:
        name = f"**{repo.split('/')[-1]}**"
        priority = remediation_priority.application_priority(matches)
        if priority:
            sentences.append(f"{name} {_LEAD[priority]}")
        else:
            sentences.append(f"{name} has updates and no CVE decision")
    return ". ".join(sentences) + "." if sentences else "No applications."


def _app_section(number: int, repo: str, matches: list[dict]) -> list[str]:
    name = repo.split("/")[-1]
    priority = remediation_priority.application_priority(matches)
    pulls = (
        f"https://github.com/{repo}/pulls?q=is%3Apr+is%3Aopen+label%3Alightwell"
    )
    heading = f"## {number}. [{name}](https://github.com/{repo})"
    if priority:
        heading = f"{heading} {_badge(priority)}"
    ordered = _ordered_matches(matches)
    with_cves = [match for match in ordered if match.get("cves")]
    without = [match for match in ordered if not match.get("cves")]
    shown = with_cves or without
    lines = [
        heading,
        "",
        _MEANING.get(priority, "No CVE on these updates, so there is no patch decision."),
        "",
        f"[Open pull request]({pulls})",
        "",
        "<details>",
        f"<summary>{_count_label(_cve_count(matches))} · libraries</summary>",
        "",
        "| Library | Now → Lightwell | CVEs | Decision |",
        "|---------|-----------------|------|----------|",
    ]
    for match in shown:
        update = f"{match.get('fromVersion')} → {match.get('toVersion')}"
        lines.append(
            f"| {match.get('artifactId')} | {update} | {_cve_cell(match)} | "
            f"{_badge(remediation_priority.match_priority(match))} |"
        )
    if with_cves and without:
        extras = ", ".join(
            f"{match.get('artifactId')} {match.get('fromVersion')} → {match.get('toVersion')}"
            for match in without
        )
        lines.extend(["", f"Updates with no CVE: {extras}."])
    lines.extend(["", "</details>", ""])
    return lines


def render_dashboard(apps: list[tuple[str, list[dict]]]) -> str:
    """Markdown page. ``apps`` is ``(owner/name, matches)``; urgent apps come first."""
    ordered = _ordered_apps(apps)
    lines = [
        '<h1 align="center">CVE Remediation Dashboard</h1>',
        "",
        _lead(ordered),
        "",
        "## When to patch",
        "",
        "| Decision | When |",
        "|----------|------|",
        f"| {_badge('Immediate')} | Act now |",
        f"| {_badge('Out-of-Cycle')} | Security patch, ahead of the feature release |",
        f"| {_badge('Scheduled')} | Next planned release |",
        f"| {_badge('Defer')} | Track. No patch this cycle |",
        "",
        "| # | Application | Decision | CVEs |",
        "|---|-------------|----------|------|",
    ]
    for number, (repo, matches) in enumerate(ordered, start=1):
        name = repo.split("/")[-1]
        link = f"[{name}](https://github.com/{repo})"
        priority = remediation_priority.application_priority(matches)
        lines.append(
            f"| {number} | {link} | {_badge(priority)} | {_count_label(_cve_count(matches))} |"
        )
    lines.append("")
    for number, (repo, matches) in enumerate(ordered, start=1):
        lines.extend(_app_section(number, repo, matches))
    return "\n".join(lines).rstrip() + "\n"


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
