#!/usr/bin/env python3
"""Write a shields.io endpoint JSON badge for available Lightwell library updates.

The message keeps the update count and, when the scan has one, the same
application priority the remediation pull request shows.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import remediation_priority

_COUNT_COLOR = "0E4429"


def badge_message(matches: list) -> tuple[str, str]:
    """Right-hand badge text and color. Priority matches the application row."""
    count = len(matches)
    if count == 0:
        return "0 available", "informational"
    available = "1 available" if count == 1 else f"{count} available"
    priority = remediation_priority.application_priority(matches)
    if not priority:
        return available, _COUNT_COLOR
    return f"{priority} · {available}", remediation_priority.priority_color(priority)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matches",
        type=Path,
        required=True,
        help="Path to matches.json from scan_poms.py",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output badge JSON path (e.g. lightwell-badge.json)",
    )
    args = parser.parse_args()

    matches = json.loads(args.matches.read_text(encoding="utf-8")).get("matches", [])
    message, color = badge_message(matches)

    payload = {
        "schemaVersion": 1,
        "label": "Lightwell library updates",
        "message": message,
        "color": color,
        "cacheSeconds": 60,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
