#!/usr/bin/env python3
"""Write a shields.io endpoint JSON badge for available Lightwell library updates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


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
    count = len(matches)
    if count == 0:
        message = "0 available"
        color = "informational"
    elif count == 1:
        message = "1 available"
        color = "0E4429"
    else:
        message = f"{count} available"
        color = "0E4429"

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
