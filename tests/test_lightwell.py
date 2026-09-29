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
import osv_cves  # noqa: E402
import scan_poms  # noqa: E402
import write_badge  # noqa: E402


FIXTURE_POM = (Path(__file__).parent / "fixtures" / "pom.xml").read_text(encoding="utf-8")
FIXTURE_OSV = Path(__file__).parent / "fixtures" / "osv"

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
    def test_parses_inline_versions_skips_unresolved_and_plugin(self) -> None:
        deps = scan_poms.parse_dependencies(FIXTURE_POM, pom_label="fixture")
        coords = {(d["groupId"], d["artifactId"], d["version"]) for d in deps}
        self.assertIn(("commons-io", "commons-io", "2.11.0"), coords)
        self.assertIn(("org.springframework", "spring-core", "5.3.18"), coords)
        # Unresolved ${skipped.version} and missing version skipped; plugin dep skipped.
        self.assertEqual(len(deps), 2)

    def test_resolves_property_versions(self) -> None:
        text = """
        <project>
          <properties>
            <jackson.version>2.13.4</jackson.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
              <version>${jackson.version}</version>
            </dependency>
          </dependencies>
        </project>
        """
        deps = scan_poms.parse_dependencies(text)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["version"], "2.13.4")
        self.assertEqual(deps[0]["versionProperty"], "jackson.version")

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

    def test_apply_property_version(self) -> None:
        text = """
        <project>
          <properties>
            <jackson.version>2.13.4</jackson.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
              <version>${jackson.version}</version>
            </dependency>
          </dependencies>
        </project>
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(text, encoding="utf-8")
            catalog = [
                {
                    "groupId": "com.fasterxml.jackson.core",
                    "artifactId": "jackson-databind",
                    "fromVersion": "2.13.4",
                    "toVersion": "2.13.4.rhlw-00001",
                }
            ]
            matches = scan_poms.match_remediations(root, catalog, set())
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["versionProperty"], "jackson.version")
            self.assertTrue(apply_bumps.apply_match(root, matches[0]))
            updated = (root / "pom.xml").read_text(encoding="utf-8")
            self.assertIn("<jackson.version>2.13.4.rhlw-00001</jackson.version>", updated)

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

    def test_serviced_other_version_match_not_applied(self) -> None:
        catalog = [
            {
                "groupId": "org.yaml",
                "artifactId": "snakeyaml",
                "fromVersion": "1.33.0",
                "toVersion": "1.33.0.rhlw-00001",
                "tier": "validated",
                "summary": "snakeyaml serviced",
            }
        ]
        pom_text = """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.yaml</groupId>
              <artifactId>snakeyaml</artifactId>
              <version>1.30</version>
            </dependency>
          </dependencies>
        </project>
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(pom_text, encoding="utf-8")
            matches = scan_poms.match_remediations(root, catalog, set())
            self.assertEqual(len(matches), 1)
            m = matches[0]
            self.assertEqual(m["matchKind"], "serviced_other_version")
            self.assertFalse(m["apply"])
            self.assertEqual(m["fromVersion"], "1.30")
            self.assertEqual(m["toVersion"], "1.33.0.rhlw-00001")
            self.assertEqual(m["servicedVersions"], ["1.33.0.rhlw-00001"])

            matches_path = root / "matches.json"
            matches_path.write_text(
                json.dumps({"matches": matches}), encoding="utf-8"
            )
            argv = [
                "apply_bumps.py",
                "--root",
                str(root),
                "--matches",
                str(matches_path),
            ]
            old = sys.argv
            try:
                sys.argv = argv
                self.assertEqual(apply_bumps.main(), 0)
            finally:
                sys.argv = old
            self.assertIn("<version>1.30</version>", (root / "pom.xml").read_text())


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
                    "matchKind": "drop_in",
                    "meaning": scan_poms.MEANING_DROP_IN,
                    "servicedVersions": ["2.11.0.rhlw-1"],
                    "cves": [],
                    "max_cvss": None,
                    "max_severity": None,
                }
            ]
        )
        self.assertIn("lightwell/remediations", report)
        self.assertNotIn("confirm=open-pr", report)
        self.assertNotIn("Lightwell Open PR", report)
        self.assertIn("CVEs fixed", report)

    def test_report_includes_cve_table_and_links(self) -> None:
        report = scan_poms.render_report(
            [
                {
                    "pom": "pom.xml",
                    "groupId": "org.springframework",
                    "artifactId": "spring-core",
                    "fromVersion": "5.3.18",
                    "toVersion": "5.3.18.rhlw-00001",
                    "tier": "remediated",
                    "matchKind": "drop_in",
                    "meaning": scan_poms.MEANING_DROP_IN,
                    "servicedVersions": ["5.3.18.rhlw-00001"],
                    "summary": "test",
                    "cves": [
                        {
                            "id": "CVE-2023-20863",
                            "cvss": 6.5,
                            "severity": "MEDIUM",
                            "summary": "Spring SpEL DoS.",
                        }
                    ],
                    "max_cvss": 6.5,
                    "max_severity": "MEDIUM",
                }
            ]
        )
        self.assertIn(
            "| Dependency | You run | Serviced versions | What it means for you | CVEs fixed (CVSS) |",
            report,
        )
        self.assertIn("CVE-2023-20863", report)
        self.assertIn("6.5", report)
        self.assertIn("MEDIUM", report)
        self.assertIn("access.redhat.com/security/cve/CVE-2023-20863", report)
        # Table cell (Proposed bumps) must be a clickable Red Hat Access link + severity.
        self.assertIn(
            "[`CVE-2023-20863`](https://access.redhat.com/security/cve/CVE-2023-20863) (6.5 MEDIUM)",
            report,
        )
        self.assertNotIn("| Highest |", report)
        self.assertNotIn("nvd.nist.gov", report)

    def test_report_serviced_other_version_in_bumps_table_only(self) -> None:
        report = scan_poms.render_report(
            [
                {
                    "pom": "pom.xml",
                    "groupId": "org.yaml",
                    "artifactId": "snakeyaml",
                    "fromVersion": "1.30",
                    "toVersion": "1.33.0.rhlw-00001",
                    "tier": "validated",
                    "matchKind": "serviced_other_version",
                    "meaning": scan_poms.MEANING_SERVICED_OTHER,
                    "apply": False,
                    "servicedVersions": ["1.33.0.rhlw-00001"],
                    "cves": [
                        {
                            "id": "CVE-2022-1471",
                            "cvss": 8.3,
                            "severity": "HIGH",
                            "summary": "SnakeYAML constructor",
                        }
                    ],
                    "max_cvss": 8.3,
                    "max_severity": "HIGH",
                }
            ]
        )
        self.assertIn("Serviced — at a different version", report)
        self.assertIn("`org.yaml:snakeyaml`", report)
        self.assertIn("`1.30`", report)
        self.assertIn("`1.33.0.rhlw-00001`", report)
        self.assertIn("CVE-2022-1471", report)
        self.assertIn("Move to a serviced version, or request your version.", report)
        # Informational only — not in the proposed pom diff
        self.assertNotIn("+  <version>1.33.0.rhlw-00001</version>", report)
        self.assertIn("no drop-in pom edits", report)


class OsvCveTests(unittest.TestCase):
    def test_cvss_base_score_known_vectors(self) -> None:
        # Network DoS vector used by several Lightwell advisories → 7.5
        score = osv_cves.cvss_v3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        )
        self.assertEqual(score, 7.5)
        self.assertEqual(osv_cves.severity_rating(score), "HIGH")

        score_med = osv_cves.cvss_v3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
        )
        self.assertEqual(score_med, 6.5)
        self.assertEqual(osv_cves.severity_rating(score_med), "MEDIUM")

    def test_format_cve_inline_markdown_link_and_severity(self) -> None:
        self.assertEqual(
            osv_cves.format_cve_inline(
                {"id": "CVE-2023-20863", "cvss": 6.5, "severity": "MEDIUM"}
            ),
            "[`CVE-2023-20863`](https://access.redhat.com/security/cve/CVE-2023-20863) (6.5 MEDIUM)",
        )
        self.assertEqual(
            osv_cves.format_cve_inline({"id": "CVE-2099-0001"}),
            "[`CVE-2099-0001`](https://access.redhat.com/security/cve/CVE-2099-0001)",
        )

    def test_severity_fallback_via_ghsa_alias(self) -> None:
        # Lightwell demo OSV sometimes omits severity; GHSA alias supplies CVSS.
        lightwell_doc = {
            "id": "x_RHLW-CVE-2023-51074-2.8.0",
            "aliases": ["GHSA-pfh2-hfmq-phg5", "CVE-2023-51074"],
            "severity": [],
        }
        osv_cves._OSV_DEV_CACHE.clear()
        osv_cves._OSV_DEV_CACHE["GHSA-pfh2-hfmq-phg5"] = {
            "id": "GHSA-pfh2-hfmq-phg5",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                }
            ],
        }
        score, rating, vector = osv_cves.severity_with_fallback(lightwell_doc)
        self.assertEqual(score, 5.3)
        self.assertEqual(rating, "MEDIUM")
        self.assertIn("AV:N", vector or "")
        osv_cves._OSV_DEV_CACHE.clear()

    def test_attach_cves_from_local_osv_and_sort(self) -> None:
        matches = [
            {
                "pom": "pom.xml",
                "groupId": "commons-io",
                "artifactId": "commons-io",
                "fromVersion": "2.11.0",
                "toVersion": "2.11.0.redhat-00001",
            },
            {
                "pom": "pom.xml",
                "groupId": "org.springframework",
                "artifactId": "spring-core",
                "fromVersion": "5.3.18",
                "toVersion": "5.3.18.rhlw-00001",
            },
            {
                "pom": "pom.xml",
                "groupId": "com.jayway.jsonpath",
                "artifactId": "json-path",
                "fromVersion": "2.8.0",
                "toVersion": "2.8.0.rhlw-00001",
            },
        ]
        records = osv_cves.load_osv_records_from_dir(FIXTURE_OSV)
        self.assertGreaterEqual(len(records), 3)
        osv_cves.attach_cves_to_matches(matches, records)

        # Sorted by max CVSS desc: json-path 7.5, spring-core 6.5, commons-io low
        self.assertEqual(matches[0]["artifactId"], "json-path")
        self.assertEqual(matches[0]["max_cvss"], 7.5)
        self.assertEqual(matches[0]["cves"][0]["id"], "CVE-2023-51074")

        self.assertEqual(matches[1]["artifactId"], "spring-core")
        self.assertEqual(matches[1]["max_cvss"], 6.5)
        self.assertEqual(matches[1]["cves"][0]["id"], "CVE-2023-20863")

        self.assertEqual(matches[2]["artifactId"], "commons-io")
        self.assertEqual(matches[2]["cves"][0]["id"], "CVE-2099-0001")
        self.assertLess(matches[2]["max_cvss"], 4.0)

    def test_elevate_only_when_osv_fixed_is_published(self) -> None:
        """Hybrid: elevate to OSV fixed only if the Maven artifact exists."""
        records = [
            {
                "id": "x_RHLW-CVE-2025-41249-5.3.18",
                "aliases": ["CVE-2025-41249"],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    }
                ],
                "affected": [
                    {
                        "package": {
                            "ecosystem": "Maven",
                            "name": "org.springframework:spring-core",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "5.3.18.rhlw-00010"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]

        unpublished = [
            {
                "pom": "pom.xml",
                "groupId": "org.springframework",
                "artifactId": "spring-core",
                "fromVersion": "5.3.18",
                "toVersion": "5.3.18.rhlw-00003",
            }
        ]
        osv_cves.attach_cves_to_matches(
            unpublished,
            records,
            require_published=True,
            exists_fn=lambda *_a, **_k: False,
        )
        self.assertEqual(unpublished[0]["toVersion"], "5.3.18.rhlw-00003")
        self.assertEqual(unpublished[0]["laterOsvFixed"], "5.3.18.rhlw-00010")
        self.assertEqual(unpublished[0]["cves"], [])
        self.assertEqual(unpublished[0]["pendingCves"][0]["id"], "CVE-2025-41249")

        published = [
            {
                "pom": "pom.xml",
                "groupId": "org.springframework",
                "artifactId": "spring-core",
                "fromVersion": "5.3.18",
                "toVersion": "5.3.18.rhlw-00003",
            }
        ]
        osv_cves.attach_cves_to_matches(
            published,
            records,
            require_published=True,
            exists_fn=lambda *_a, **_k: True,
        )
        self.assertEqual(published[0]["toVersion"], "5.3.18.rhlw-00010")
        self.assertNotIn("laterOsvFixed", published[0])
        self.assertEqual(published[0]["cves"][0]["id"], "CVE-2025-41249")
        self.assertEqual(published[0]["cves"][0]["fixed_in"], "5.3.18.rhlw-00010")

    def test_no_invented_cves_without_osv(self) -> None:
        matches = [
            {
                "pom": "pom.xml",
                "groupId": "org.springframework",
                "artifactId": "spring-core",
                "fromVersion": "5.3.18",
                "toVersion": "5.3.18.rhlw-00001",
            }
        ]
        osv_cves.attach_cves_to_matches(matches, [])
        self.assertEqual(matches[0]["cves"], [])
        self.assertIsNone(matches[0]["max_cvss"])


class SyncCatalogVersionOrderTests(unittest.TestCase):
    def test_numeric_rhlw_build_beats_lexicographic_trap(self) -> None:
        import sync_catalog

        # Equal-width padded suffixes can look fine as strings; uneven widths do not:
        # "0009" > "00010" lexicographically, but build 9 < 10.
        self.assertTrue("5.3.18.rhlw-0009" > "5.3.18.rhlw-00010")
        self.assertTrue(
            sync_catalog.is_newer_rhlw(
                "5.3.18.rhlw-00010", "5.3.18.rhlw-0009"
            )
        )
        self.assertTrue(
            sync_catalog.is_newer_rhlw(
                "5.3.18.rhlw-00010", "5.3.18.rhlw-00003"
            )
        )
        self.assertEqual(sync_catalog.rhlw_build_num("5.3.18.rhlw-00010"), 10)

    def test_merge_keeps_highest_numeric_build(self) -> None:
        import sync_catalog

        merged = sync_catalog.merge_remediations(
            [
                {
                    "groupId": "org.springframework",
                    "artifactId": "spring-core",
                    "fromVersion": "5.3.18",
                    "toVersion": "5.3.18.rhlw-00003",
                    "tier": "remediated",
                    "summary": "older",
                },
                {
                    "groupId": "org.springframework",
                    "artifactId": "spring-core",
                    "fromVersion": "5.3.18",
                    "toVersion": "5.3.18.rhlw-00010",
                    "tier": "remediated",
                    "summary": "newer",
                },
            ]
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["toVersion"], "5.3.18.rhlw-00010")


if __name__ == "__main__":
    unittest.main()
