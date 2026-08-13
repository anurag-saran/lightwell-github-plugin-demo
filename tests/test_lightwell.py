#!/usr/bin/env python3
"""Unit tests for Lightwell scan/apply/badge helpers."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "lightwell-github"
sys.path.insert(0, str(PLUGIN))

import apply_bumps  # noqa: E402
import scan_poms  # noqa: E402
import write_badge  # noqa: E402


FIXTURE_POM = (Path(__file__).parent / "fixtures" / "pom.xml").read_text(encoding="utf-8")

SAMPLE_CATALOG = [
    {
        "groupId": "commons-io",
        "artifactId": "commons-io",
        "fromVersion": "2.11.0",
        "toVersion": "2.11.0.redhat-00001",
        "tier": "validated",
        "summary": "test remediation",
    },
    {
        "groupId": "org.springframework",
        "artifactId": "spring-core",
        "fromVersion": "5.3.18",
        "toVersion": "5.3.18.rhlw-00001",
        "tier": "remediated",
        "summary": "test remediation",
    },
]


class ParseDependenciesTests(unittest.TestCase):
    def test_parses_inline_versions_skips_property_and_plugin(self) -> None:
        deps = scan_poms.parse_dependencies(FIXTURE_POM, pom_label="fixture")
        coords = {(d["groupId"], d["artifactId"], d["version"]) for d in deps}
        self.assertIn(("commons-io", "commons-io", "2.11.0"), coords)
        self.assertIn(("org.springframework", "spring-core", "5.3.18"), coords)
        # Property version and missing version skipped; plugin dep skipped.
        self.assertEqual(len(deps), 2)

    def test_no_namespace_pom(self) -> None:
        text = """
        <project>
          <dependencies>
            <dependency>
              <groupId>commons-io</groupId>
              <artifactId>commons-io</artifactId>
              <version>2.11.0</version>
            </dependency>
          </dependencies>
        </project>
        """
        deps = scan_poms.parse_dependencies(text)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["artifactId"], "commons-io")


class MatchAndApplyTests(unittest.TestCase):
    def test_match_and_apply_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pom = root / "pom.xml"
            pom.write_text(FIXTURE_POM, encoding="utf-8")
            matches = scan_poms.match_remediations(root, SAMPLE_CATALOG, set())
            self.assertEqual(len(matches), 2)
            for match in matches:
                self.assertTrue(apply_bumps.apply_match(root, match))
            deps = scan_poms.parse_dependencies(pom.read_text(encoding="utf-8"))
            versions = {(d["groupId"], d["artifactId"], d["version"]) for d in deps}
            self.assertIn(("commons-io", "commons-io", "2.11.0.redhat-00001"), versions)
            self.assertIn(("org.springframework", "spring-core", "5.3.18.rhlw-00001"), versions)

    def test_apply_fails_on_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(FIXTURE_POM, encoding="utf-8")
            bad = {
                "pom": "pom.xml",
                "groupId": "commons-io",
                "artifactId": "commons-io",
                "fromVersion": "9.9.9",
                "toVersion": "9.9.9.rhlw-1",
            }
            self.assertFalse(apply_bumps.apply_match(root, bad))


class CatalogSchemaTests(unittest.TestCase):
    def test_load_catalog_rejects_missing_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(
                json.dumps({"remediations": [{"groupId": "x"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                scan_poms.load_catalog(path)

    def test_load_real_catalog(self) -> None:
        rem = scan_poms.load_catalog(PLUGIN / "catalog.json")
        self.assertGreaterEqual(len(rem), 1)


class BadgeTests(unittest.TestCase):
    def test_badge_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            matches_path = Path(tmp) / "matches.json"
            out = Path(tmp) / "badge.json"
            for count, message, color in [
                (0, "0 available", "informational"),
                (1, "1 available", "0E4429"),
                (3, "3 available", "0E4429"),
            ]:
                matches_path.write_text(
                    json.dumps({"matches": [{}] * count}),
                    encoding="utf-8",
                )
                # Call write_badge main via argv
                argv = ["write_badge.py", "--matches", str(matches_path), "--out", str(out)]
                old = sys.argv
                try:
                    sys.argv = argv
                    self.assertEqual(write_badge.main(), 0)
                finally:
                    sys.argv = old
                payload = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual(payload["message"], message)
                self.assertEqual(payload["color"], color)


class ReportTests(unittest.TestCase):
    def test_report_mentions_auto_pr_not_confirm(self) -> None:
        report = scan_poms.render_report(
            [
                {
                    "pom": "pom.xml",
                    "groupId": "commons-io",
                    "artifactId": "commons-io",
                    "fromVersion": "2.11.0",
                    "toVersion": "2.11.0.rhlw-1",
                    "summary": "",
                }
            ]
        )
        self.assertIn("lightwell/remediations", report)
        self.assertNotIn("confirm=open-pr", report)
        self.assertNotIn("Lightwell Open PR", report)


if __name__ == "__main__":
    unittest.main()
