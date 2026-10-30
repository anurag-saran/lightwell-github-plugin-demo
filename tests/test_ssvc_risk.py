#!/usr/bin/env python3
"""SSVC table pin, token mapping, fallbacks, and report rendering."""

from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "lightwell-github"
sys.path.insert(0, str(PLUGIN))

import scan_poms  # noqa: E402
import ssvc_risk  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "ssvc"


def _config(**overrides: object) -> dict:
    cfg = {
        "human_impact": None,
        "exposure": None,
        "overrides": {},
        "demo": False,
        "warnings": [],
    }
    cfg.update(overrides)
    return cfg


def _risk(
    cve_id: str = "CVE-2024-0001",
    *,
    in_kev: bool = False,
    adp: dict | None = None,
    epss: float | None = None,
    config: dict | None = None,
) -> dict:
    return ssvc_risk.build_cve_risk(
        cve_id,
        in_kev=in_kev,
        adp=adp,
        epss=epss,
        epss_fetched_at="2026-10-29" if epss is not None else None,
        config=config or _config(),
        fetched_at="2026-10-29",
    )


def _cve(cve_id: str, risk: dict, cvss: float | None = None) -> dict:
    return {"id": cve_id, "cvss": cvss, "risk": risk}


def _match(artifact: str, cves: list[dict]) -> dict:
    return {
        "groupId": "org.example",
        "artifactId": artifact,
        "fromVersion": "1.0",
        "toVersion": "1.0.rhlw-00001",
        "pom": "pom.xml",
        "cves": cves,
        "_risk_meta": {"as_of": "2026-10-29", "table": ssvc_risk.TABLE_VERSION},
    }


class TablePinTests(unittest.TestCase):
    def test_sha256_row_count_and_unique_combinations(self) -> None:
        self.assertEqual(ssvc_risk.table_sha256(), ssvc_risk.EXPECTED_SHA256)
        text = ssvc_risk.TABLE_PATH.read_text(encoding="utf-8")
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(len(rows[0]), 6)
        self.assertIn(",", rows[0][5])
        self.assertIn("Defer", rows[0][5])
        data = rows[1:]
        self.assertEqual(len(data), 72)
        keys = [(row[1], row[2], row[3], row[4]) for row in data]
        self.assertEqual(len(set(keys)), 72)
        self.assertNotIn(rows[0][5], {row[5] for row in data})

    def test_verified_csv_rows(self) -> None:
        cases = {
            ("none", "small", "no", "low"): "defer",
            ("public poc", "controlled", "yes", "medium"): "scheduled",
            ("active", "controlled", "no", "medium"): "scheduled",
            ("active", "open", "no", "medium"): "out-of-cycle",
            ("active", "open", "yes", "very high"): "immediate",
            ("active", "controlled", "yes", "medium"): "out-of-cycle",
            ("active", "open", "yes", "medium"): "out-of-cycle",
        }
        for key, outcome in cases.items():
            self.assertEqual(ssvc_risk.lookup(*key), outcome, key)


class TokenTests(unittest.TestCase):
    def test_vulnrichment_tokens(self) -> None:
        self.assertEqual(ssvc_risk.map_exploitation("poc"), "public poc")
        self.assertEqual(ssvc_risk.map_exploitation("POC"), "public poc")
        self.assertEqual(ssvc_risk.map_exploitation("none"), "none")
        self.assertEqual(ssvc_risk.map_exploitation("active"), "active")
        self.assertEqual(ssvc_risk.map_automatable("yes"), "yes")
        self.assertEqual(ssvc_risk.map_automatable("no"), "no")

    def test_unknown_tokens_are_missing_and_fall_back(self) -> None:
        self.assertIsNone(ssvc_risk.map_exploitation("weaponized"))
        self.assertIsNone(ssvc_risk.map_automatable("maybe"))
        risk = _risk(adp={"exploitation": "weaponized", "automatable": "maybe"})
        self.assertEqual(risk["exploitation"]["value"], "Public PoC")
        self.assertTrue(risk["exploitation"]["assumed"])
        self.assertEqual(risk["exploitation"]["source"], "assumed")
        self.assertEqual(risk["automatable"]["value"], "Yes")
        self.assertTrue(risk["automatable"]["assumed"])
        self.assertIsNone(risk["exploitation"]["fetched_at"])


class DecisionTests(unittest.TestCase):
    def test_kev_fixture_sets_exploitation_active(self) -> None:
        kev = json.loads((FIX / "kev.json").read_text(encoding="utf-8"))
        self.assertIn("CVE-2021-44228", ssvc_risk.kev_ids_from_doc(kev))
        adp = ssvc_risk.parse_adp(
            json.loads((FIX / "CVE-2021-44228.json").read_text(encoding="utf-8"))
        )
        self.assertIsNotNone(adp)
        assert adp is not None
        self.assertEqual(adp["exploitation"], "active")
        self.assertEqual(adp["automatable"], "yes")
        risk = _risk(
            "CVE-2021-44228",
            in_kev=True,
            adp={"exploitation": "poc", "automatable": "yes", "fetched_at": "2026-10-29"},
            config=_config(human_impact="medium"),
        )
        self.assertEqual(risk["exploitation"]["value"], "Active")
        self.assertEqual(risk["exploitation"]["source"], "cisa-kev")
        self.assertFalse(risk["exploitation"]["assumed"])
        self.assertEqual(risk["exploitation"]["fetched_at"], "2026-10-29")

    def test_missing_adp_uses_conservative_defaults(self) -> None:
        risk = _risk(adp=None, epss=None)
        self.assertEqual(risk["exploitation"]["value"], "Public PoC")
        self.assertTrue(risk["exploitation"]["assumed"])
        self.assertEqual(risk["automatable"]["value"], "Yes")
        self.assertTrue(risk["automatable"]["assumed"])
        self.assertEqual(risk["human_impact"]["value"], "Medium")
        self.assertTrue(risk["human_impact"]["assumed"])
        self.assertEqual(risk["outcome_internal"], "Scheduled")
        self.assertEqual(risk["outcome_external"], "Scheduled")
        self.assertIsNone(risk["epss"])
        self.assertIsNone(json.loads(json.dumps(risk))["epss"])

    def test_columns_differ_for_active_not_automatable(self) -> None:
        risk = _risk(
            adp={"exploitation": "active", "automatable": "no"},
            config=_config(human_impact="medium"),
        )
        self.assertEqual(risk["outcome_internal"], "Scheduled")
        self.assertEqual(risk["outcome_external"], "Out-of-Cycle")
        self.assertIn("Exposure=Controlled", risk["trace_internal"])
        self.assertIn("→ Scheduled", risk["trace_internal"])
        self.assertIn("Exposure=Open", risk["trace_external"])
        self.assertIn("→ Out-of-Cycle", risk["trace_external"])

    def test_active_open_very_high_is_immediate(self) -> None:
        risk = _risk(
            adp={"exploitation": "active", "automatable": "yes"},
            config=_config(human_impact="very high"),
        )
        self.assertEqual(risk["outcome_external"], "Immediate")
        self.assertEqual(
            ssvc_risk.lookup("active", "open", "yes", "very high"),
            "immediate",
        )

    def test_poc_token_from_live_adp_fixture(self) -> None:
        adp = ssvc_risk.parse_adp(
            json.loads((FIX / "CVE-2024-6387.json").read_text(encoding="utf-8"))
        )
        assert adp is not None
        self.assertEqual(ssvc_risk.map_exploitation(adp["exploitation"]), "public poc")
        self.assertEqual(ssvc_risk.map_automatable(adp["automatable"]), "no")
        epss = ssvc_risk.parse_epss(json.loads((FIX / "epss.json").read_text(encoding="utf-8")))
        self.assertAlmostEqual(epss["CVE-2021-44228"], 0.99999)
        self.assertNotIn("CVE-2099-00000", epss)

    def test_demo_high_impact_splits_the_columns(self) -> None:
        risk = _risk(config=_config(human_impact="high", demo=True))
        self.assertEqual(risk["human_impact"]["value"], "High")
        self.assertEqual(risk["human_impact"]["source"], "config")
        self.assertTrue(risk["demo_setting"])
        self.assertEqual(risk["outcome_internal"], "Scheduled")
        self.assertEqual(risk["outcome_external"], "Out-of-Cycle")
        section = ssvc_risk.render_section([_match("spring-core", [_cve("CVE-1", risk, 5.0)])])
        self.assertIn("High*", section)
        self.assertIn("selected for this demo", section)
        self.assertIn("source CMDB", section)
        self.assertNotIn("(demo setting)", section)
        self.assertNotIn("(assumed)", section)
        self.assertIn("## SSVC priority: ![Out-of-Cycle]", section)
        self.assertIn("Highest across these libraries:", section)
        self.assertIn("Exploitation<br>[CISA ADP](https://github.com/cisagov/vulnrichment)", section)
        self.assertIn("App impact<br>CMDB", section)
        self.assertIn("EPSS<br>[FIRST](https://www.first.org/epss/)", section)
        header = next(line for line in section.splitlines() if line.startswith("| CVE |"))
        self.assertLess(header.index("EPSS"), header.index("Exploitation"))
        self.assertNotIn("Exploited?", section)
        self.assertIn("If the app is internal", section)
        self.assertIn("![Scheduled](https://img.shields.io/badge/Scheduled-a16207", section)
        self.assertIn(
            "![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c",
            section,
        )
        self.assertIn("Outcome key", section)
        self.assertIn("Where the columns come from:", section)
        self.assertIn("App impact was selected for this demo", section)
        self.assertIn(
            "SSVC data found for 0 of 1 CVEs; 2 values had no source record.",
            section,
        )
        self.assertIn("[5](https://access.redhat.com/security/cve/CVE-1)", section)
        self.assertIn("https://github.com/cisagov/vulnrichment", section)
        self.assertIn("https://www.first.org/epss/", section)
        self.assertIn("Risk data as of 2026-10-29 · SSVC table deployer_patch_application_priority_1_0_0", section)

    def test_override_and_declared_exposure(self) -> None:
        risk = _risk(
            "CVE-2024-0000",
            adp={"exploitation": "poc", "automatable": "yes"},
            config=_config(
                human_impact="medium",
                exposure="external",
                overrides={
                    "CVE-2024-0000": {
                        "exploitation": "active",
                        "automatable": "no",
                        "note": "Mythos finding #123",
                    }
                },
            ),
        )
        self.assertEqual(risk["exploitation"]["value"], "Active")
        self.assertEqual(risk["exploitation"]["source"], "customer-provided")
        self.assertEqual(risk["automatable"]["value"], "No")
        self.assertEqual(risk["outcome_internal"], "Scheduled")
        self.assertEqual(risk["outcome_external"], "Out-of-Cycle")
        section = ssvc_risk.render_section(
            [_match("json-path", [_cve("CVE-2024-0000", risk, 7.5)])]
        )
        self.assertIn("## SSVC priority: ![Out-of-Cycle]", section)
        self.assertIn("if the app is external (declared)", section)
        self.assertIn("Out-of-Cycle (declared)", section)
        self.assertNotIn("Scheduled (declared)", section)
        self.assertIn("Mythos finding #123", section)
        self.assertIn("source customer-provided", section)

    def test_invalid_config_fields_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".lightwell-risk.json"
            path.write_text(
                json.dumps(
                    {
                        "human_impact": "catastrophic",
                        "exposure": "space",
                        "overrides": {
                            "CVE-1": {
                                "exploitation": "everywhere",
                                "automatable": "No",
                                "note": "keep me",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            cfg = ssvc_risk.load_risk_config(path, demo=False)
        self.assertIsNone(cfg["human_impact"])
        self.assertIsNone(cfg["exposure"])
        self.assertNotIn("exploitation", cfg["overrides"]["CVE-1"])
        self.assertEqual(cfg["overrides"]["CVE-1"]["automatable"], "no")
        self.assertEqual(cfg["overrides"]["CVE-1"]["note"], "keep me")
        self.assertGreaterEqual(len(cfg["warnings"]), 3)

    def test_target_config_wins_over_risk_config_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".lightwell-risk.json").write_text(
                json.dumps({"human_impact": "Low"}),
                encoding="utf-8",
            )
            fallback = root / "demo.json"
            fallback.write_text(json.dumps({"human_impact": "High"}), encoding="utf-8")
            cfg = ssvc_risk.resolve_config(root, fallback)
        self.assertEqual(cfg["human_impact"], "low")
        self.assertFalse(cfg["demo"])


class OrderingTests(unittest.TestCase):
    def test_sort_outcomes_then_epss_then_cvss_and_empty_last(self) -> None:
        immediate = _cve(
            "CVE-IMM",
            _risk(
                adp={"exploitation": "active", "automatable": "yes"},
                config=_config(human_impact="very high"),
                epss=0.1,
            ),
            cvss=1.0,
        )
        out_of_cycle = _cve(
            "CVE-OOC",
            _risk(
                adp={"exploitation": "active", "automatable": "no"},
                config=_config(human_impact="medium"),
                epss=0.99,
            ),
            cvss=9.0,
        )
        higher_epss = _cve(
            "CVE-EPSS-HIGH",
            _risk(epss=0.9, config=_config(human_impact="medium")),
            cvss=1.0,
        )
        lower_epss = _cve(
            "CVE-EPSS-LOW",
            _risk(epss=0.2, config=_config(human_impact="medium")),
            cvss=9.0,
        )
        missing_epss = _cve(
            "CVE-EPSS-NONE",
            _risk(epss=None, config=_config(human_impact="medium")),
            cvss=10.0,
        )
        matches = [
            _match("none-yet", []),
            _match("low-epss", [lower_epss]),
            _match("immediate-lib", [immediate]),
            _match("missing-epss", [missing_epss]),
            _match("high-epss", [higher_epss]),
            _match("cycle", [out_of_cycle]),
        ]
        ssvc_risk.sort_matches(matches)
        self.assertEqual(
            [m["artifactId"] for m in matches],
            [
                "immediate-lib",
                "cycle",
                "high-epss",
                "low-epss",
                "missing-epss",
                "none-yet",
            ],
        )
        section = ssvc_risk.render_section(matches)
        self.assertIn("## SSVC priority: ![Immediate]", section)
        self.assertIn(
            "[Active](https://www.cve.org/CVERecord?id=CVE-IMM)",
            section,
        )
        self.assertIn(
            "[0.10000](https://api.first.org/data/v1/epss?cve=CVE-IMM)",
            section,
        )
        self.assertLess(section.index("CVE-IMM"), section.index("CVE-OOC"))
        self.assertLess(section.index("CVE-EPSS-HIGH"), section.index("CVE-EPSS-LOW"))
        self.assertLess(section.index("CVE-EPSS-LOW"), section.index("CVE-EPSS-NONE"))
        self.assertIn("| — | none-yet 1.0 → 1.0.rhlw-00001 | — | — | — | — | — | — | — |", section)
        self.assertLess(section.index("CVE-EPSS-NONE"), section.index("none-yet"))
        none_row = next(line for line in section.splitlines() if line.startswith("| — |"))
        self.assertIn("n/a", section)
        self.assertNotIn("n/a", none_row)

    def test_epss_batches_stay_at_most_100(self) -> None:
        ids = [f"CVE-2099-{i:05d}" for i in range(101)]
        batches = ssvc_risk.epss_batches(ids)
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), 100)
        self.assertEqual(len(batches[1]), 1)
        self.assertTrue(all(len(batch) <= 100 for batch in batches))
        with self.assertRaises(ValueError):
            ssvc_risk.epss_batches(ids, size=101)

    def test_offline_reads_the_cache_and_does_not_fetch(self) -> None:
        calls: list[str] = []

        def boom(url: str) -> dict:
            calls.append(url)
            raise AssertionError(url)

        original = ssvc_risk._http_json
        ssvc_risk._http_json = boom
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cache = root / "feeds"
                (cache / "adp").mkdir(parents=True)
                (cache / "kev.json").write_text(
                    json.dumps({"fetched_at": "2026-10-01", "cve_ids": ["CVE-2021-44228"]}),
                    encoding="utf-8",
                )
                (cache / "adp" / "CVE-2021-44228.json").write_text(
                    json.dumps(
                        {
                            "fetched_at": "2026-10-01",
                            "exploitation": "poc",
                            "automatable": "no",
                        }
                    ),
                    encoding="utf-8",
                )
                (cache / "epss.json").write_text(
                    json.dumps(
                        {
                            "fetched_at": "2026-10-01",
                            "scores": {"CVE-2021-44228": 0.5, "CVE-2099-00001": None},
                        }
                    ),
                    encoding="utf-8",
                )
                matches = [
                    _match(
                        "log4j",
                        [
                            {"id": "CVE-2021-44228", "cvss": 10.0},
                            {"id": "CVE-2099-00001", "cvss": 5.0},
                        ],
                    )
                ]
                ssvc_risk.apply_risk(
                    matches,
                    root=root,
                    cache_dir=cache,
                    offline=True,
                    now="2026-10-29",
                )
        finally:
            ssvc_risk._http_json = original
        self.assertEqual(calls, [])
        known = matches[0]["cves"][0]["risk"]
        missing = matches[0]["cves"][1]["risk"]
        self.assertEqual(known["exploitation"]["value"], "Active")
        self.assertEqual(known["exploitation"]["source"], "cisa-kev")
        self.assertEqual(known["automatable"]["value"], "No")
        self.assertEqual(known["epss"], 0.5)
        self.assertEqual(missing["exploitation"]["value"], "Public PoC")
        self.assertTrue(missing["exploitation"]["assumed"])
        self.assertIsNone(missing["epss"])
        self.assertEqual(ssvc_risk.format_epss(missing["epss"]), "n/a")


class PrBodyTests(unittest.TestCase):
    def test_short_report_keeps_traces(self) -> None:
        report = "hello\n<details><summary>How this was computed: CVE-1</summary>\npath\n</details>\n"
        body = scan_poms.render_pr_body(report, 1)
        self.assertIn("<details>", body)
        self.assertLessEqual(len(body), scan_poms.PR_BODY_LIMIT)
        self.assertIn("## Test plan", body)

    def test_long_report_drops_traces_and_links_report(self) -> None:
        blocks = []
        for i in range(200):
            blocks.append(
                f"<details><summary>How this was computed: CVE-{i}</summary>\n"
                + ("x" * 500)
                + "\n</details>\n"
            )
        report = "intro\n" + "".join(blocks)
        body = scan_poms.render_pr_body(report, 3)
        self.assertLessEqual(len(body), scan_poms.PR_BODY_LIMIT)
        self.assertNotIn("<details>", body)
        self.assertIn("report.md", body)
        self.assertIn("intro", body)


if __name__ == "__main__":
    unittest.main()
