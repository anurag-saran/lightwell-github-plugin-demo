#!/usr/bin/env python3
"""Unit tests for the app priority dashboard."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lightwell-github"))

import write_dashboard  # noqa: E402


def _match(
    artifact: str,
    current: str,
    update: str,
    cves: list[dict] | None = None,
    *,
    external: str | None = None,
    internal: str | None = None,
) -> dict:
    entry: dict = {
        "artifactId": artifact,
        "fromVersion": current,
        "toVersion": update,
        "cves": cves or [],
    }
    if external or internal:
        for cve in entry["cves"]:
            cve["risk"] = {
                "outcome_external": external,
                "outcome_internal": internal or external,
            }
    return entry


class DashboardTests(unittest.TestCase):
    def test_two_apps_keep_priority_libraries_and_cves(self) -> None:
        page = write_dashboard.render_dashboard(
            [
                (
                    "anurag-saran/payments-service",
                    [
                        _match(
                            "json",
                            "20220320",
                            "20220320.0.0.rhlw-00003",
                            [{"id": "CVE-2022-45688", "cvss": 7.5, "severity": "HIGH"}],
                            external="Out-of-Cycle",
                        ),
                        _match(
                            "woodstox-core",
                            "6.0.3",
                            "6.0.3.rhlw-00001",
                            [{"id": "CVE-2022-40152"}],
                            external="Scheduled",
                        ),
                    ],
                ),
                (
                    "anurag-saran/fraud-service",
                    [
                        _match(
                            "logback-classic",
                            "1.2.11",
                            "1.2.11.rhlw-00001",
                            [{"id": "CVE-2021-42550"}],
                            external="Scheduled",
                        )
                    ],
                ),
            ]
        )
        self.assertIn(
            "[payments-service](https://github.com/anurag-saran/payments-service)",
            page,
        )
        self.assertIn(
            "[fraud-service](https://github.com/anurag-saran/fraud-service)",
            page,
        )
        self.assertIn("Out--of--Cycle-c2410c", page)
        self.assertIn("Scheduled-a16207", page)
        self.assertIn("json 20220320 → 20220320.0.0.rhlw-00003", page)
        self.assertIn("woodstox-core 6.0.3 → 6.0.3.rhlw-00001", page)
        self.assertIn("logback-classic 1.2.11 → 1.2.11.rhlw-00001", page)
        self.assertIn("CVE-2022-45688", page)
        self.assertIn("CVE-2022-40152", page)
        self.assertIn("CVE-2021-42550", page)
        self.assertLess(
            page.index("payments-service"),
            page.index("fraud-service"),
        )

    def test_missing_priority_is_a_dash(self) -> None:
        page = write_dashboard.render_dashboard(
            [
                (
                    "anurag-saran/payments-service",
                    [
                        _match(
                            "json",
                            "20220320",
                            "20220320.0.0.rhlw-00003",
                            [{"id": "CVE-2022-45688"}],
                        )
                    ],
                )
            ]
        )
        self.assertIn("| — | json 20220320 → 20220320.0.0.rhlw-00003 |", page)
        self.assertNotIn("shields.io", page)

    def test_app_with_no_cves(self) -> None:
        page = write_dashboard.render_dashboard(
            [
                (
                    "anurag-saran/fraud-service",
                    [_match("commons-fileupload", "1.4.0", "1.4.0.rhlw-00001", [])],
                )
            ]
        )
        self.assertIn(
            "commons-fileupload 1.4.0 → 1.4.0.rhlw-00001 | — |",
            page,
        )

    def test_cli_writes_the_page(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matches = root / "matches.json"
            out = root / "dashboard.md"
            matches.write_text(
                json.dumps(
                    {
                        "matches": [
                            _match(
                                "json",
                                "20220320",
                                "20220320.0.0.rhlw-00003",
                                [{"id": "CVE-2023-5072"}],
                                external="Defer",
                            )
                        ]
                    }
                ),
                encoding="utf-8",
            )
            old = sys.argv
            try:
                sys.argv = [
                    "write_dashboard.py",
                    "--app",
                    f"anurag-saran/payments-service={matches}",
                    "--out",
                    str(out),
                ]
                self.assertEqual(write_dashboard.main(), 0)
            finally:
                sys.argv = old
            text = out.read_text(encoding="utf-8")
            self.assertIn("Defer-15803d", text)
            self.assertIn("CVE-2023-5072", text)


if __name__ == "__main__":
    unittest.main()
