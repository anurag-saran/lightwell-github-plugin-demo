#!/usr/bin/env python3
"""Sync lightwell-github/catalog.json from public Lightwell demo Maven indexes.

Crawls the unauthenticated validated and remediated feeds under
https://packages.redhat.com/lightwell/public-lightwell-demo/java/ and rewrites
catalog.json so GitHub Actions stay aligned with the Hybrid Cloud Console demos.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_REPOS: dict[str, str] = {
    "validated": (
        "https://packages.redhat.com/lightwell/public-lightwell-demo/java/validated/"
    ),
    "remediated": (
        "https://packages.redhat.com/lightwell/public-lightwell-demo/java/remediated/"
    ),
}

HREF_DIR_RE = re.compile(r'href="\./([^"/]+)/"')
RHLW_VERSION_RE = re.compile(r"^(?P<base>.+)\.rhlw-(?P<build>\d+)$")
USER_AGENT = "mta-openwire-demo-lightwell-catalog-sync/1.0"


def fetch_text(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def list_dirs(index_html: str) -> list[str]:
    names: list[str] = []
    for match in HREF_DIR_RE.finditer(index_html):
        name = match.group(1)
        if name in {".", "..", ".meta"}:
            continue
        names.append(name)
    return names


def join_url(base: str, *parts: str) -> str:
    url = base if base.endswith("/") else base + "/"
    for part in parts:
        url += part.strip("/") + "/"
    return url


def parse_rhlw(version: str) -> tuple[str, str] | None:
    match = RHLW_VERSION_RE.match(version)
    if not match:
        return None
    return match.group("base"), match.group("build")


def crawl_tier(tier: str, base_url: str) -> list[dict[str, str]]:
    """Return remediations found under one Maven repository root."""
    found: list[dict[str, str]] = []

    def walk(path_parts: list[str]) -> None:
        url = join_url(base_url, *path_parts)
        try:
            html = fetch_text(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return
            raise
        except urllib.error.URLError:
            raise

        children = list_dirs(html)
        version_dirs = [c for c in children if parse_rhlw(c)]
        other_dirs = [c for c in children if not parse_rhlw(c)]

        # Maven layout: .../<group path>/<artifactId>/<version>/
        if version_dirs and len(path_parts) >= 2:
            artifact_id = path_parts[-1]
            group_id = ".".join(path_parts[:-1])
            # Prefer highest .rhlw-NNNNN build per upstream base version.
            best: dict[str, tuple[str, str]] = {}
            for version in version_dirs:
                parsed = parse_rhlw(version)
                if not parsed:
                    continue
                base, build = parsed
                prev = best.get(base)
                if prev is None or build > prev[1]:
                    best[base] = (version, build)
            for from_version, (to_version, _) in sorted(best.items()):
                found.append(
                    {
                        "groupId": group_id,
                        "artifactId": artifact_id,
                        "fromVersion": from_version,
                        "toVersion": to_version,
                        "tier": tier,
                        "summary": (
                            f"Lightwell {tier} rebuild of "
                            f"{artifact_id} {from_version}"
                        ),
                    }
                )
            return

        for child in other_dirs:
            walk([*path_parts, child])

    walk([])
    return found


def merge_remediations(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Collapse duplicates across tiers; keep one row per GAV fromVersion."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        key = (entry["groupId"], entry["artifactId"], entry["fromVersion"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(entry)
            continue

        # Prefer the lexicographically greater toVersion (newer rhlw build).
        if entry["toVersion"] > existing["toVersion"]:
            tiers = sorted(
                {
                    *existing.get("tier", "").split("+"),
                    entry["tier"],
                }
                - {""}
            )
            existing.update(entry)
            existing["tier"] = "+".join(tiers) if len(tiers) > 1 else entry["tier"]
            existing["summary"] = (
                f"Lightwell rebuild of {entry['artifactId']} "
                f"{entry['fromVersion']} ({existing['tier']} demo feed"
                f"{'s' if '+' in existing['tier'] else ''})"
            )
            continue

        # Same/older build: just union tiers when toVersion matches.
        if entry["toVersion"] == existing["toVersion"]:
            tiers = sorted(
                {
                    *existing.get("tier", "").split("+"),
                    entry["tier"],
                }
                - {""}
            )
            if len(tiers) > 1:
                existing["tier"] = "+".join(tiers)
                existing["summary"] = (
                    f"Lightwell rebuild of {entry['artifactId']} "
                    f"{entry['fromVersion']} (validated and remediated demo feeds)"
                )

    return sorted(
        merged.values(),
        key=lambda r: (r["tier"], r["groupId"], r["artifactId"], r["fromVersion"]),
    )


def build_catalog(repos: dict[str, str]) -> dict[str, Any]:
    all_entries: list[dict[str, str]] = []
    for tier, url in repos.items():
        print(f"Crawling {tier}: {url}", file=sys.stderr)
        tier_entries = crawl_tier(tier, url)
        print(f"  found {len(tier_entries)} artifact version(s)", file=sys.stderr)
        all_entries.extend(tier_entries)
    return {
        "remediations": merge_remediations(all_entries),
        "repositories": repos,
    }


def catalog_fingerprint(data: dict[str, Any]) -> str:
    """Stable comparison payload (ignore formatting-only drift)."""
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("lightwell-github/catalog.json"),
        help="Path to catalog.json to update",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if catalog would change; do not write",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print new catalog JSON to stdout; do not write",
    )
    args = parser.parse_args()

    catalog_path = args.catalog
    new_data = build_catalog(DEFAULT_REPOS)
    new_text = json.dumps(new_data, indent=2) + "\n"

    old_text = ""
    if catalog_path.is_file():
        old_data = json.loads(catalog_path.read_text(encoding="utf-8"))
        old_text = catalog_fingerprint(old_data)
    changed = catalog_fingerprint(new_data) != old_text

    if args.dry_run:
        sys.stdout.write(new_text)
        return 0

    if args.check:
        if changed:
            print(f"Catalog out of date: {catalog_path}", file=sys.stderr)
            return 1
        print(f"Catalog up to date: {catalog_path}", file=sys.stderr)
        return 0

    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    catalog_path.write_text(new_text, encoding="utf-8")
    count = len(new_data["remediations"])
    state = "updated" if changed else "unchanged"
    print(f"Wrote {catalog_path} ({count} remediations, {state})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
