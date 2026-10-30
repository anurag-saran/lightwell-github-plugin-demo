#!/usr/bin/env python3
"""Remediation Priority Engine (RPE): applies CERT/CC's SSVC deployer table to Lightwell matches.

The decision table is the vendored CERT/CC CSV. This module does not encode
outcomes itself. It only gathers Exploitation, Automatable, Human Impact, and
the two exposure columns, then looks up the row.

Both columns are always computed: internal = Controlled, external = Open.
Missing data never lowers urgency: unknown tokens are treated as missing and
the conservative fallback is used.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TABLE_PATH = (
    Path(__file__).resolve().parent
    / "ssvc"
    / "deployer_patch_application_priority_1_0_0.csv"
)
TABLE_VERSION = "deployer_patch_application_priority_1_0_0"
TABLE_COMMIT = "bf3213bc0bd2bf3cf1329c9b48f72d7163a682b1"
EXPECTED_SHA256 = "68491dc72505bf0703f32d8a278fc59cdaee4f515922633312bf4cc67f1b1aab"
EXPECTED_ROWS = 72

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# access.redhat.com redirects here. The year is the year in the CVE ID.
RH_VEX_URL = "https://security.access.redhat.com/data/csaf/v2/vex/{year}/{name}.json"
RH_CVE_PAGE = "https://access.redhat.com/security/cve/{cve_id_lower}"
CVE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
EPSS_BATCH = 100
USER_AGENT = "lightwell-github-plugin-demo"

DEFAULT_FEED_CACHE = Path(__file__).resolve().parent / "out" / "feeds"

# Column positions in the vendored CSV. The outcome header is quoted and
# contains commas, so these indexes are the contract, not the header text.
_COL_EXPLOITATION = 1
_COL_EXPOSURE = 2
_COL_AUTOMATABLE = 3
_COL_IMPACT = 4
_COL_OUTCOME = 5

_EXPLOITATION = {
    "none": "none",
    "poc": "public poc",
    "public poc": "public poc",
    "active": "active",
}
_AUTOMATABLE = {"yes": "yes", "no": "no"}
_IMPACT = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "very high": "very high",
}
_EXPOSURE_CONFIG = {
    "internal": "internal",
    "external": "external",
}

_DISPLAY = {
    "none": "None",
    "public poc": "Public PoC",
    "active": "Active",
    "yes": "Yes",
    "no": "No",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "very high": "Very High",
    "small": "Small",
    "controlled": "Controlled",
    "open": "Open",
    "defer": "Defer",
    "scheduled": "Scheduled",
    "out-of-cycle": "Out-of-Cycle",
    "immediate": "Immediate",
}

_RANK = {"Immediate": 0, "Out-of-Cycle": 1, "Scheduled": 2, "Defer": 3}

_TABLE: dict[tuple[str, str, str, str], str] | None = None


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def table_sha256(path: Path | None = None) -> str:
    raw = (path or TABLE_PATH).read_bytes()
    return hashlib.sha256(raw).hexdigest()


def load_table(path: Path | None = None) -> dict[tuple[str, str, str, str], str]:
    """Map (exploitation, exposure, automatable, human impact) to the outcome token."""
    global _TABLE
    if path is None and _TABLE is not None:
        return _TABLE
    text = (path or TABLE_PATH).read_text(encoding="utf-8")
    table: dict[tuple[str, str, str, str], str] = {}
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0] == "row":
            continue
        key = (
            row[_COL_EXPLOITATION],
            row[_COL_EXPOSURE],
            row[_COL_AUTOMATABLE],
            row[_COL_IMPACT],
        )
        table[key] = row[_COL_OUTCOME]
    if path is None:
        _TABLE = table
    return table


def lookup(
    exploitation: str,
    exposure: str,
    automatable: str,
    human_impact: str,
    table: dict[tuple[str, str, str, str], str] | None = None,
) -> str | None:
    rows = table if table is not None else load_table()
    return rows.get((exploitation, exposure, automatable, human_impact))


def display(token: str) -> str:
    return _DISPLAY[token]


def _norm(raw: object) -> str:
    return " ".join(str(raw).strip().lower().split())


def map_exploitation(raw: object | None) -> str | None:
    """Map a Vulnrichment or config exploitation token onto the CSV.

    Vulnrichment uses ``poc``. The CSV token is ``public poc``. ``none`` and
    ``active`` pass through. Anything else is missing.
    """
    if raw is None:
        return None
    return _EXPLOITATION.get(_norm(raw))


def map_automatable(raw: object | None) -> str | None:
    """Map ``yes`` / ``no``. Anything else is missing."""
    if raw is None:
        return None
    return _AUTOMATABLE.get(_norm(raw))


def map_human_impact(raw: object | None) -> str | None:
    if raw is None:
        return None
    return _IMPACT.get(_norm(raw))


def map_exposure(raw: object | None) -> str | None:
    if raw is None:
        return None
    return _EXPOSURE_CONFIG.get(_norm(raw))


def parse_adp(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """Pull Exploitation and Automatable out of a CVE Services record.

    CISA publishes these under ``containers.adp`` where
    ``providerMetadata.shortName`` is ``CISA-ADP``, on the metric whose
    ``other.type`` is ``ssvc``. ``options`` is a list of single-key objects.
    A cached record already flattened to those two fields is accepted too.
    """
    if not isinstance(doc, dict) or doc.get("missing"):
        return None
    if "containers" not in doc and "exploitation" in doc:
        if doc.get("exploitation") is None and doc.get("automatable") is None:
            return None
        return {
            "exploitation": doc.get("exploitation"),
            "automatable": doc.get("automatable"),
            "timestamp": doc.get("timestamp"),
            "fetched_at": doc.get("fetched_at"),
        }
    for container in (doc.get("containers") or {}).get("adp") or []:
        if not isinstance(container, dict):
            continue
        provider = container.get("providerMetadata") or {}
        if provider.get("shortName") != "CISA-ADP":
            continue
        for metric in container.get("metrics") or []:
            other = (metric or {}).get("other") or {}
            if other.get("type") != "ssvc":
                continue
            content = other.get("content") or {}
            found: dict[str, Any] = {}
            for item in content.get("options") or []:
                if isinstance(item, dict):
                    found.update(item)
            return {
                "exploitation": found.get("Exploitation"),
                "automatable": found.get("Automatable"),
                "timestamp": content.get("timestamp"),
                "fetched_at": doc.get("fetched_at"),
            }
    return None


def kev_ids_from_doc(doc: dict[str, Any] | None) -> set[str]:
    if not isinstance(doc, dict):
        return set()
    if "cve_ids" in doc and "vulnerabilities" not in doc:
        return {str(c) for c in doc.get("cve_ids") or [] if c}
    found = set()
    for vuln in doc.get("vulnerabilities") or []:
        if isinstance(vuln, dict) and vuln.get("cveID"):
            found.add(str(vuln["cveID"]))
    return found


def parse_epss(doc: dict[str, Any] | None) -> dict[str, float]:
    scores: dict[str, float] = {}
    if not isinstance(doc, dict):
        return scores
    for row in doc.get("data") or []:
        if not isinstance(row, dict) or not row.get("cve") or row.get("epss") is None:
            continue
        scores[str(row["cve"])] = round(float(row["epss"]), 10)
    return scores


def epss_batches(cve_ids: list[str], size: int = EPSS_BATCH) -> list[list[str]]:
    if size < 1 or size > EPSS_BATCH:
        raise ValueError(f"EPSS batch size must be 1..{EPSS_BATCH}")
    return [cve_ids[i : i + size] for i in range(0, len(cve_ids), size)]


def load_risk_config(path: Path | None, *, demo: bool) -> dict[str, Any]:
    """Load a risk config. Invalid fields are dropped and recorded in warnings."""
    cfg: dict[str, Any] = {
        "human_impact": None,
        "exposure": None,
        "overrides": {},
        "demo": demo,
        "warnings": [],
    }
    if path is None:
        return cfg
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        cfg["warnings"].append(f"ignoring risk config {path}: {exc}")
        return cfg
    if not isinstance(raw, dict):
        cfg["warnings"].append(f"ignoring risk config {path}: expected an object")
        return cfg
    if "human_impact" in raw:
        mapped = map_human_impact(raw.get("human_impact"))
        if mapped:
            cfg["human_impact"] = mapped
        else:
            cfg["warnings"].append(
                f"ignoring human_impact {raw.get('human_impact')!r} in {path}"
            )
    if "exposure" in raw:
        mapped = map_exposure(raw.get("exposure"))
        if mapped:
            cfg["exposure"] = mapped
        else:
            cfg["warnings"].append(
                f"ignoring exposure {raw.get('exposure')!r} in {path}"
            )
    overrides = raw.get("overrides", {})
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, dict):
        cfg["warnings"].append(f"ignoring overrides in {path}: expected an object")
        overrides = {}
    clean: dict[str, dict[str, str]] = {}
    for cve_id, body in overrides.items():
        if not isinstance(body, dict):
            cfg["warnings"].append(f"ignoring override for {cve_id}: expected an object")
            continue
        entry: dict[str, str] = {}
        for field, mapper in (
            ("exploitation", map_exploitation),
            ("automatable", map_automatable),
            ("human_impact", map_human_impact),
        ):
            if field not in body:
                continue
            mapped = mapper(body.get(field))
            if mapped:
                entry[field] = mapped
            else:
                cfg["warnings"].append(
                    f"ignoring {cve_id} {field} {body.get(field)!r} in {path}"
                )
        note = body.get("note")
        if isinstance(note, str) and note.strip():
            entry["note"] = note.strip()
        clean[str(cve_id)] = entry
    cfg["overrides"] = clean
    return cfg


def resolve_config(root: Path, risk_config: Path | None) -> dict[str, Any]:
    """Prefer ``.lightwell-rpe.json``. ``--rpe-config`` is the demo fallback.

    ``.lightwell-risk.json`` still loads, with a warning, when the new file is absent.
    """
    current = root / ".lightwell-rpe.json"
    legacy = root / ".lightwell-risk.json"
    if current.is_file():
        if legacy.is_file():
            warn("ignoring legacy .lightwell-risk.json; using .lightwell-rpe.json")
        return load_risk_config(current, demo=False)
    if legacy.is_file():
        warn("using legacy .lightwell-risk.json; rename it to .lightwell-rpe.json")
        return load_risk_config(legacy, demo=False)
    if risk_config is not None:
        return load_risk_config(risk_config, demo=True)
    return load_risk_config(None, demo=False)


def _point(
    token: str,
    source: str,
    fetched_at: str | None,
    assumed: bool,
    note: str | None = None,
) -> dict[str, Any]:
    point: dict[str, Any] = {
        "value": display(token),
        "source": source,
        "fetched_at": fetched_at if not assumed else None,
        "assumed": assumed,
    }
    if note:
        point["note"] = note
    return point


def _trace(exploitation: str, exposure: str, automatable: str, impact: str, outcome: str) -> str:
    return (
        f"Exploitation={display(exploitation)} · Exposure={display(exposure)} · "
        f"Automatable={display(automatable)} · Human Impact={display(impact)} "
        f"→ {display(outcome)}"
    )


def _conservative(token: str | None, default: str) -> str:
    """A missing lookup must not lower urgency."""
    return token or "immediate"


def rh_vex_url(cve_id: str) -> str | None:
    parts = cve_id.split("-")
    if len(parts) < 3 or not parts[1].isdigit() or len(parts[1]) != 4:
        return None
    return RH_VEX_URL.format(year=parts[1], name=cve_id.lower())


def rh_cve_page(cve_id: str) -> str:
    return RH_CVE_PAGE.format(cve_id_lower=cve_id.lower())


def parse_redhat_vex(doc: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Red Hat exploit status for one CVE.

    ``exploited`` when that CVE has a threat of category ``exploit_status``.
    ``not_listed`` when it has a threats array and no such entry.
    ``None`` when Red Hat published no answer: the CVE is absent, or there is
    no threats array. A missing threats array does not mean "not exploited".
    """
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        return None
    match = next(
        (
            vuln
            for vuln in vulns
            if isinstance(vuln, dict) and vuln.get("cve") == cve_id
        ),
        None,
    )
    if match is None:
        return None
    threats = match.get("threats")
    if not isinstance(threats, list):
        return None
    for threat in threats:
        if isinstance(threat, dict) and threat.get("category") == "exploit_status":
            return {
                "status": "exploited",
                "date": threat.get("date"),
                "details": threat.get("details"),
            }
    return {"status": "not_listed"}


def build_cve_risk(
    cve_id: str,
    *,
    in_kev: bool,
    adp: dict[str, Any] | None,
    epss: float | None,
    epss_fetched_at: str | None,
    config: dict[str, Any],
    fetched_at: str | None,
    redhat: dict[str, Any] | None = None,
    table: dict[tuple[str, str, str, str], str] | None = None,
) -> dict[str, Any]:
    rows = table if table is not None else load_table()
    override = (config.get("overrides") or {}).get(cve_id) or {}
    note = override.get("note")
    adp = adp or {}
    redhat = redhat or {}

    adp_fetched = adp.get("fetched_at") or fetched_at
    if override.get("exploitation"):
        expl_token = override["exploitation"]
        exploitation = _point(expl_token, "customer-provided", None, False, note)
    elif redhat.get("status") == "exploited":
        expl_token = "active"
        listed = redhat.get("date")
        rh_note = "CISA KEV via Red Hat"
        if listed:
            rh_note = f"{rh_note}, listed {listed}"
        exploitation = _point(
            expl_token,
            "redhat-vex",
            redhat.get("fetched_at") or fetched_at,
            False,
            rh_note,
        )
    elif in_kev:
        expl_token = "active"
        lag = (
            "Red Hat record not yet updated"
            if redhat.get("status") == "not_listed"
            else None
        )
        exploitation = _point(expl_token, "cisa-kev", fetched_at, False, lag)
    else:
        mapped = map_exploitation(adp.get("exploitation"))
        if mapped:
            expl_token = mapped
            exploitation = _point(expl_token, "cisa-adp", adp_fetched, False)
        else:
            expl_token = "public poc"
            exploitation = _point(expl_token, "assumed", None, True)

    if override.get("automatable"):
        auto_token = override["automatable"]
        automatable = _point(auto_token, "customer-provided", None, False, note)
    else:
        mapped_auto = map_automatable(adp.get("automatable"))
        if mapped_auto:
            auto_token = mapped_auto
            automatable = _point(auto_token, "cisa-adp", adp_fetched, False)
        else:
            auto_token = "yes"
            automatable = _point(auto_token, "assumed", None, True)

    if override.get("human_impact"):
        impact = _point(override["human_impact"], "customer-provided", None, False, note)
        impact_token = override["human_impact"]
    elif config.get("human_impact"):
        impact = _point(config["human_impact"], "config", None, False)
        impact_token = config["human_impact"]
    else:
        impact = _point("medium", "assumed", None, True)
        impact_token = "medium"

    internal_token = _conservative(
        lookup(expl_token, "controlled", auto_token, impact_token, rows),
        "immediate",
    )
    external_token = _conservative(
        lookup(expl_token, "open", auto_token, impact_token, rows),
        "immediate",
    )
    risk: dict[str, Any] = {
        "exploitation": exploitation,
        "automatable": automatable,
        "human_impact": impact,
        "outcome_internal": display(internal_token),
        "outcome_external": display(external_token),
        "exposure_declared": config.get("exposure"),
        "epss": epss,
        "epss_fetched_at": epss_fetched_at if epss is not None else None,
        "trace_internal": _trace(
            expl_token, "controlled", auto_token, impact_token, internal_token
        ),
        "trace_external": _trace(
            expl_token, "open", auto_token, impact_token, external_token
        ),
        "demo_setting": bool(config.get("demo")) and impact["source"] == "config",
    }
    if note:
        risk["note"] = note
    return risk


def _rank_key(cve: dict[str, Any]) -> tuple[Any, ...]:
    risk = cve.get("risk") or {}
    epss = risk.get("epss")
    cvss = cve.get("cvss")
    epss_known = isinstance(epss, (int, float))
    cvss_known = isinstance(cvss, (int, float))
    return (
        _RANK.get(risk.get("outcome_external"), 0),
        _RANK.get(risk.get("outcome_internal"), 0),
        0 if epss_known else 1,
        -(float(epss) if epss_known else 0.0),
        0 if cvss_known else 1,
        -(float(cvss) if cvss_known else 0.0),
    )


def sort_matches(matches: list[dict[str, Any]]) -> None:
    """Most urgent external outcome first. Matches with no CVEs sort last."""

    def key(match: dict[str, Any]) -> tuple[Any, ...]:
        cves = [c for c in (match.get("cves") or []) if c.get("risk")]
        name = (match.get("artifactId") or "", match.get("groupId") or "")
        if not cves:
            return (1, 0, 0, 0, 0.0, 0, 0.0, name)
        worst = min(cves, key=_rank_key)
        return (0, *_rank_key(worst), name)

    matches.sort(key=key)


def coverage_counts(matches: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Return (cves with any CISA decision point, cve count, assumed values)."""
    found = 0
    total = 0
    assumed = 0
    for match in matches:
        for cve in match.get("cves") or []:
            risk = cve.get("risk")
            if not risk:
                continue
            total += 1
            got_feed = False
            for name in ("exploitation", "automatable", "human_impact"):
                point = risk.get(name) or {}
                if point.get("assumed"):
                    assumed += 1
                elif name != "human_impact":
                    got_feed = True
            if got_feed:
                found += 1
    return found, total, assumed


def exploit_status_counts(matches: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Return (Red Hat Active, CVE count, CISA KEV fallback)."""
    redhat = 0
    total = 0
    kev = 0
    for match in matches:
        for cve in match.get("cves") or []:
            risk = cve.get("risk")
            if not risk:
                continue
            total += 1
            source = (risk.get("exploitation") or {}).get("source")
            if source == "redhat-vex":
                redhat += 1
            elif source == "cisa-kev":
                kev += 1
    return redhat, total, kev


def _day(value: str | None) -> str | None:
    if not value:
        return None
    return str(value)[:10]


def _http_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object from {url}")
    return payload


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _fetch_redhat(
    cve_ids: list[str], cache_dir: Path, offline: bool, now: str
) -> dict[str, dict[str, Any] | None]:
    """One parsed VEX result per CVE. Never raises. None means Red Hat had no answer."""
    found: dict[str, dict[str, Any] | None] = {}
    for cve_id in cve_ids:
        path = cache_dir / "redhat" / f"{cve_id}.json"
        url = rh_vex_url(cve_id)
        if not offline and url:
            try:
                parsed = parse_redhat_vex(_http_json(url), cve_id)
                payload: dict[str, Any] = {"fetched_at": now}
                if parsed:
                    payload.update(parsed)
                _write_json(path, payload)
                found[cve_id] = payload if parsed else None
                continue
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    _write_json(path, {"fetched_at": now, "missing": True})
                    found[cve_id] = None
                    continue
                warn(f"{cve_id}: Red Hat VEX fetch failed ({exc}); using the cache if present")
            except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                warn(f"{cve_id}: Red Hat VEX fetch failed ({exc}); using the cache if present")
        cached = _read_json(path)
        if cached and cached.get("status") in ("exploited", "not_listed"):
            found[cve_id] = cached
        else:
            if cached is None:
                warn(f"{cve_id}: no cached Red Hat VEX record")
            found[cve_id] = None
    return found


def _fetch_kev(cache_dir: Path, offline: bool, now: str) -> tuple[set[str], str | None]:
    path = cache_dir / "kev.json"
    if not offline:
        try:
            doc = _http_json(KEV_URL)
            ids = sorted(kev_ids_from_doc(doc))
            _write_json(path, {"fetched_at": now, "cve_ids": ids})
            return set(ids), now
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            warn(f"KEV fetch failed ({exc}); using the cache if present")
    cached = _read_json(path)
    if cached and "cve_ids" in cached:
        if not offline:
            warn("using cached KEV catalog")
        return set(kev_ids_from_doc(cached)), cached.get("fetched_at")
    warn("KEV catalog unavailable; Exploitation falls back to Public PoC where ADP is missing")
    return set(), None


def _fetch_adp(
    cve_ids: list[str], cache_dir: Path, offline: bool, now: str
) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for cve_id in cve_ids:
        path = cache_dir / "adp" / f"{cve_id}.json"
        if not offline:
            try:
                doc = _http_json(CVE_URL.format(cve_id=cve_id))
                parsed = parse_adp(doc) or {}
                payload = {
                    "fetched_at": now,
                    "exploitation": parsed.get("exploitation"),
                    "automatable": parsed.get("automatable"),
                    "timestamp": parsed.get("timestamp"),
                }
                _write_json(path, payload)
                if parsed.get("exploitation") or parsed.get("automatable"):
                    found[cve_id] = payload
                continue
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    _write_json(
                        path,
                        {
                            "fetched_at": now,
                            "missing": True,
                            "exploitation": None,
                            "automatable": None,
                        },
                    )
                    continue
                warn(f"{cve_id}: CVE record fetch failed ({exc}); using the cache if present")
            except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                warn(f"{cve_id}: CVE record fetch failed ({exc}); using the cache if present")
        cached = _read_json(path)
        parsed = parse_adp(cached)
        if parsed:
            found[cve_id] = parsed
        elif cached is None:
            warn(f"{cve_id}: no cached CISA ADP record")
    return found


def _fetch_epss(
    cve_ids: list[str], cache_dir: Path, offline: bool, now: str
) -> tuple[dict[str, float | None], str | None]:
    path = cache_dir / "epss.json"
    cached = _read_json(path) or {}
    stored = cached.get("scores") if isinstance(cached.get("scores"), dict) else {}
    if offline:
        scores: dict[str, float | None] = {}
        for cve_id in cve_ids:
            raw = stored.get(cve_id) if cve_id in stored else None
            scores[cve_id] = float(raw) if isinstance(raw, (int, float)) else None
        return scores, cached.get("fetched_at")

    fresh: dict[str, float | None] = {}
    fetched_at: str | None = now
    for batch in epss_batches(cve_ids):
        try:
            doc = _http_json(EPSS_URL + ",".join(batch))
            parsed = parse_epss(doc)
            for cve_id in batch:
                fresh[cve_id] = parsed.get(cve_id)
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            warn(f"EPSS fetch failed for {len(batch)} CVE(s) ({exc}); using cached scores")
            fetched_at = cached.get("fetched_at") or now
            for cve_id in batch:
                raw = stored.get(cve_id) if cve_id in stored else None
                fresh[cve_id] = float(raw) if isinstance(raw, (int, float)) else None
    merged = dict(stored)
    merged.update(fresh)
    _write_json(path, {"fetched_at": fetched_at, "scores": merged})
    return fresh, fetched_at


def _stamp(matches: list[dict[str, Any]], as_of: str) -> None:
    meta = {"as_of": as_of, "table": TABLE_VERSION}
    for match in matches:
        match["_risk_meta"] = meta


def _apply_records(
    matches: list[dict[str, Any]],
    *,
    config: dict[str, Any],
    kev: set[str],
    adp_by_cve: dict[str, dict[str, Any]],
    epss_by_cve: dict[str, float | None],
    redhat_by_cve: dict[str, dict[str, Any] | None],
    fetched_at: str | None,
    epss_fetched_at: str | None,
    as_of: str,
) -> None:
    table = load_table()
    for match in matches:
        for cve in match.get("cves") or []:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score = epss_by_cve.get(cve_id)
            cve["risk"] = build_cve_risk(
                cve_id,
                in_kev=cve_id in kev,
                adp=adp_by_cve.get(cve_id),
                epss=score if isinstance(score, (int, float)) else None,
                epss_fetched_at=epss_fetched_at,
                config=config,
                fetched_at=fetched_at,
                redhat=redhat_by_cve.get(cve_id),
                table=table,
            )
    sort_matches(matches)
    _stamp(matches, as_of)


def apply_risk(
    matches: list[dict[str, Any]],
    *,
    root: Path,
    cache_dir: Path,
    offline: bool = False,
    risk_config: Path | None = None,
    now: str | None = None,
) -> None:
    """Attach RPE outcomes. Network and parse errors fall back; they do not raise."""
    try:
        _apply_risk(
            matches,
            root=root,
            cache_dir=cache_dir,
            offline=offline,
            risk_config=risk_config,
            now=now,
        )
    except Exception as exc:
        warn(f"RPE enrichment failed ({exc}); using conservative defaults")
        try:
            config = resolve_config(root, risk_config)
            for message in config.get("warnings") or []:
                warn(message)
            as_of = _day(now) or "unknown"
            _apply_records(
                matches,
                config=config,
                kev=set(),
                adp_by_cve={},
                epss_by_cve={},
                redhat_by_cve={},
                fetched_at=None,
                epss_fetched_at=None,
                as_of=as_of,
            )
        except Exception as exc2:
            warn(f"RPE enrichment skipped ({exc2})")


def _apply_risk(
    matches: list[dict[str, Any]],
    *,
    root: Path,
    cache_dir: Path,
    offline: bool,
    risk_config: Path | None,
    now: str | None,
) -> None:
    stamp = now or datetime.now(timezone.utc).date().isoformat()
    config = resolve_config(root, risk_config)
    for message in config.get("warnings") or []:
        warn(message)
    cve_ids: list[str] = []
    seen: set[str] = set()
    for match in matches:
        for cve in match.get("cves") or []:
            cve_id = cve.get("id")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                cve_ids.append(cve_id)
    cache_dir.mkdir(parents=True, exist_ok=True)
    kev, kev_at = _fetch_kev(cache_dir, offline, stamp)
    adp = _fetch_adp(cve_ids, cache_dir, offline, stamp) if cve_ids else {}
    redhat = _fetch_redhat(cve_ids, cache_dir, offline, stamp) if cve_ids else {}
    epss, epss_at = _fetch_epss(cve_ids, cache_dir, offline, stamp) if cve_ids else ({}, None)
    dates = [d for d in (_day(kev_at), _day(epss_at), _day(stamp)) if d]
    for record in redhat.values():
        if record:
            day = _day(record.get("fetched_at"))
            if day:
                dates.append(day)
    for record in adp.values():
        day = _day(record.get("fetched_at"))
        if day:
            dates.append(day)
    as_of = max(dates) if dates else stamp
    _apply_records(
        matches,
        config=config,
        kev=kev,
        adp_by_cve=adp,
        epss_by_cve=epss,
        redhat_by_cve=redhat,
        fetched_at=_day(kev_at) or _day(stamp),
        epss_fetched_at=_day(epss_at),
        as_of=as_of,
    )


def _impact_label(point: dict[str, Any], demo: bool) -> str:
    label = str(point.get("value") or "")
    if point.get("assumed"):
        return f"{label}†"
    if demo and point.get("source") == "config":
        return f"{label}*"
    return label


def _decision_label(point: dict[str, Any]) -> str:
    label = str(point.get("value") or "")
    if point.get("assumed"):
        return f"{label}†"
    return label


def _linked_decision(point: dict[str, Any], cve_id: str | None) -> str:
    """Value text. A CISA value links to the record it was read from."""
    label = _decision_label(point)
    source = point.get("source")
    if source == "redhat-vex" and cve_id:
        return f"[{label}]({rh_cve_page(cve_id)})"
    if source == "cisa-adp" and cve_id:
        return f"[{label}](https://www.cve.org/CVERecord?id={cve_id})"
    if source == "cisa-kev":
        return f"[{label}]({_KEV_URL})"
    return label


def _epss_cell(value: float | None, cve_id: str | None) -> str:
    shown = format_epss(value)
    if value is None or not cve_id:
        return shown
    return f"[{shown}](https://api.first.org/data/v1/epss?cve={cve_id})"


def _most_urgent(outcomes: list[str]) -> str | None:
    known = [outcome for outcome in outcomes if outcome in _RANK]
    if not known:
        return None
    return min(known, key=lambda outcome: _RANK[outcome])


def _priority_rollup(
    matches: list[dict[str, Any]],
) -> tuple[str | None, str | None, str | None]:
    """Worst internal outcome, worst external outcome, and declared exposure."""
    internals: list[str] = []
    externals: list[str] = []
    declared: str | None = None
    for match in matches:
        for cve in match.get("cves") or []:
            risk = cve.get("risk") or {}
            if risk.get("outcome_internal"):
                internals.append(risk["outcome_internal"])
            if risk.get("outcome_external"):
                externals.append(risk["outcome_external"])
            if declared is None and risk.get("exposure_declared"):
                declared = risk["exposure_declared"]
    return _most_urgent(internals), _most_urgent(externals), declared


def _source_phrase(source: str, cve_id: str | None) -> str:
    if source == "cisa-adp" and cve_id:
        return f"source [CISA ADP](https://www.cve.org/CVERecord?id={cve_id})"
    if source == "redhat-vex" and cve_id:
        return f"source [Red Hat]({rh_cve_page(cve_id)})"
    if source == "cisa-kev":
        return (
            "source [CISA KEV]"
            "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
        )
    if source == "first-epss" and cve_id:
        return f"source [FIRST EPSS](https://api.first.org/data/v1/epss?cve={cve_id})"
    if source == "config":
        return "source CMDB"
    if source == "assumed":
        return "source none†"
    if source == "customer-provided":
        return "source customer-provided"
    return f"source {source}"


_CISA_ADP_URL = "https://github.com/cisagov/vulnrichment"
_FIRST_EPSS_URL = "https://www.first.org/epss/"
_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_CERT_TABLE_URL = (
    "https://github.com/CERTCC/SSVC/blob/bf3213bc0bd2bf3cf1329c9b48f72d7163a682b1/"
    "data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv"
)

# Shields badges are the colored text GitHub keeps in a pull-request table.
# A single hyphen in the badge path is the color separator; a double hyphen is a hyphen.
_OUTCOME_COLOR = {
    "Immediate": "b91c1c",
    "Out-of-Cycle": "c2410c",
    "Scheduled": "a16207",
    "Defer": "15803d",
}
_OUTCOME_MEANING = (
    ("Immediate", 'Act now (the "Big Red Button")'),
    ("Out-of-Cycle", "Security patch lane, ahead of the feature release"),
    ("Scheduled", "Next normal release"),
    ("Defer", "Track"),
)


def _shield(label: str, color: str) -> str:
    encoded = label.replace("-", "--").replace(" ", "_")
    url = f"https://img.shields.io/badge/{encoded}-{color}?style=flat-square"
    return f"![{label}]({url})"


def _outcome_label(outcome: str, declared: bool) -> str:
    label = f"{outcome} (declared)" if declared else outcome
    color = _OUTCOME_COLOR.get(outcome, "6b7280")
    return _shield(label, color)


def _outcome_index() -> list[str]:
    lines = [
        "Outcome key for **Priority**:",
        "",
        "| | Value | Meaning |",
        "|---|-------|---------|",
    ]
    for outcome, meaning in _OUTCOME_MEANING:
        lines.append(f"| {_shield(outcome, _OUTCOME_COLOR[outcome])} | {outcome} | {meaning} |")
    lines.extend(
        [
            "",
            "Where the columns come from:",
            "",
            "| Column | Source |",
            "|--------|--------|",
            "| Exploitation | Red Hat exploit status "
            "(CISA KEV, from Red Hat's VEX file), else the "
            f"[CISA KEV catalog]({_KEV_URL}), else the "
            "[CISA ADP](https://github.com/cisagov/vulnrichment) "
            "SSVC block on the [CVE record](https://www.cve.org/). |",
            "| Automatable | The same CISA ADP SSVC block. Yes or No. |",
            "| App impact | CMDB record for this application: how much harm an exploit "
            "would cause here. Low, Medium, High, or Very High. |",
            "| EPSS | [FIRST EPSS](https://www.first.org/epss/): chance of exploitation "
            "activity in the next 30 days. Used only to order ties, not as an RPE table input. |",
            "| CVSS | Base score from the Lightwell OSV advisory. "
            "The number links to the Red Hat CVE page. |",
            "",
            "† The source had no value. Exploitation then uses Public PoC and "
            "Automatable uses Yes, so the priority is not lowered. "
            "App impact then uses Medium.",
            "",
            "* App impact was selected for this demo. It was not read from a CMDB.",
            "",
        ]
    )
    return lines


def format_epss(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.5f}"


def _library_cell(match: dict[str, Any]) -> str:
    return f"{match.get('artifactId')} {match.get('fromVersion')} → {match.get('toVersion')}"


def _input_line(label: str, point: dict[str, Any], shown: str, cve_id: str | None) -> str:
    parts = [f"{label}: {shown}", _source_phrase(str(point.get("source") or ""), cve_id)]
    fetched = point.get("fetched_at")
    if fetched:
        parts.append(f"fetched {fetched}")
    if point.get("source") == "config" and shown.endswith("*"):
        parts.append("selected for this demo")
    note = point.get("note")
    if note:
        parts.append(note)
    return "- " + " · ".join(parts)


def _shown_outcome(
    internal: str | None, external: str | None, declared: str | None
) -> tuple[str | None, str]:
    """The one priority this report shows, and the exposure sentence."""
    if declared == "internal":
        return internal, "This application is declared internal."
    if declared == "external":
        return external, "This application is declared external."
    return external, "This application is external."


def _priority_heading(internal: str | None, external: str | None, declared: str | None) -> list[str]:
    """Section title plus the priority for this application."""
    headline, where = _shown_outcome(internal, external, declared)
    if not headline:
        return ["## Remediation Priority Engine (RPE)", ""]
    return [
        f"## Remediation Priority Engine (RPE): {_shield(headline, _OUTCOME_COLOR[headline])}",
        "",
        f"{where} Priority across these libraries is "
        f"{_shield(headline, _OUTCOME_COLOR[headline])}.",
        "",
    ]


def _app_impact_labels(matches: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    seen: set[str] = set()
    for match in matches:
        for cve in match.get("cves") or []:
            risk = cve.get("risk")
            if not risk:
                continue
            label = _impact_label(risk["human_impact"], bool(risk.get("demo_setting")))
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
    return ", ".join(labels) if labels else "—"


def _application_table(
    matches: list[dict[str, Any]],
    internal: str | None,
    external: str | None,
    declared: str | None,
) -> list[str]:
    """App impact and exposure once. Priority here is the most urgent across libraries."""
    outcome, _where = _shown_outcome(internal, external, declared)
    if declared == "internal":
        exposure = "Internal (declared)"
    elif declared == "external":
        exposure = "External (declared)"
    else:
        exposure = "External"
    priority = _outcome_label(outcome, declared in ("internal", "external")) if outcome else "—"
    return [
        "App impact and exposure apply to the whole application. "
        "Each CVE's Priority uses that exposure.",
        "",
        "| App impact<br>CMDB | Exposure | "
        f"[Priority]({_CERT_TABLE_URL}) |",
        "|------------|----------|----------|",
        f"| {_app_impact_labels(matches)} | {exposure} | {priority} |",
        "",
    ]


def _table_header() -> list[str]:
    return [
        "| CVE | Library (current → Lightwell build) | CVSS<br>Lightwell OSV "
        f"| EPSS<br>[FIRST]({_FIRST_EPSS_URL}) "
        f"| Exploitation<br>[CISA ADP]({_CISA_ADP_URL}) "
        f"| Automatable<br>[CISA ADP]({_CISA_ADP_URL}) "
        f"| [Priority]({_CERT_TABLE_URL}) |",
        "|-----|--------------------------------------|----------------------|"
        "------------------------|------------------------------|"
        "-----------------------------|----------|",
    ]


def render_section(matches: list[dict[str, Any]]) -> str:
    """Markdown RPE section, or an empty string when enrichment did not run."""
    if not any(m.get("_risk_meta") for m in matches):
        return ""
    meta = next(m["_risk_meta"] for m in matches if m.get("_risk_meta"))
    found, total, assumed = coverage_counts(matches)
    rh_count, rh_total, kev_count = exploit_status_counts(matches)
    internal, external, declared = _priority_rollup(matches)
    lines = [
        *_priority_heading(internal, external, declared),
        "The Remediation Priority Engine (RPE) chooses how fast to patch: Immediate, "
        "Out-of-Cycle, Scheduled, or Defer. It applies CERT/CC's SSVC decision table "
        "to four answers: Exploitation, Automatable, this application's impact, and "
        "whether the app is internal or internet-facing.",
        "",
        f"Data as of {meta.get('as_of')} · Policy: CERT/CC SSVC table {meta.get('table')}",
        "",
        f"Source data found for {found} of {total} CVEs; {assumed} values had no source record.",
        (
            f"Exploit status: Red Hat for {rh_count} of {rh_total} CVEs, "
            f"CISA KEV fallback for {kev_count}."
        ),
        "",
        *_application_table(matches, internal, external, declared),
        *_table_header(),
    ]
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    empty: list[dict[str, Any]] = []
    for match in matches:
        cves = [c for c in (match.get("cves") or []) if c.get("risk")]
        if not cves:
            empty.append(match)
            continue
        for cve in cves:
            rows.append((match, cve))
    rows.sort(key=lambda item: (*_rank_key(item[1]), item[1].get("id") or ""))
    for match, cve in rows:
        risk = cve["risk"]
        cve_id = cve.get("id")
        cvss = cve.get("cvss")
        if cvss is None:
            cvss_cell = "—"
        else:
            cvss_cell = f"[{cvss:g}](https://access.redhat.com/security/cve/{cve_id})"
        link = f"[`{cve_id}`](https://access.redhat.com/security/cve/{cve_id})"
        row_declared = risk.get("exposure_declared")
        outcome = (
            risk["outcome_internal"]
            if row_declared == "internal"
            else risk["outcome_external"]
        )
        lines.append(
            "| {cve} | {lib} | {cvss} | {epss} | {expl} | {auto} | {priority} |".format(
                cve=link,
                lib=_library_cell(match),
                cvss=cvss_cell,
                epss=_epss_cell(risk.get("epss"), cve_id),
                expl=_linked_decision(risk["exploitation"], cve_id),
                auto=_linked_decision(risk["automatable"], cve_id),
                priority=_outcome_label(outcome, row_declared in ("internal", "external")),
            )
        )
    for match in empty:
        lines.append(f"| — | {_library_cell(match)} | — | — | — | — | — |")
    lines.append("")
    lines.extend(_outcome_index())
    for match, cve in rows:
        risk = cve["risk"]
        lines.append("<details>")
        lines.append(f"<summary>How this was computed: {cve.get('id')}</summary>")
        lines.append("")
        cve_id = cve.get("id")
        lines.append(
            _input_line(
                "Exploitation",
                risk["exploitation"],
                _decision_label(risk["exploitation"]),
                cve_id,
            )
        )
        lines.append(
            _input_line(
                "Automatable",
                risk["automatable"],
                _decision_label(risk["automatable"]),
                cve_id,
            )
        )
        lines.append(
            _input_line(
                "Human Impact",
                risk["human_impact"],
                _impact_label(risk["human_impact"], bool(risk.get("demo_setting"))),
                cve_id,
            )
        )
        declared = risk.get("exposure_declared")
        if declared == "internal":
            lines.append(
                "- Exposure: internal (declared), so priority uses Controlled. "
                "The external path (Open) is below."
            )
        elif declared == "external":
            lines.append(
                "- Exposure: external (declared), so priority uses Open. "
                "The internal path (Controlled) is below."
            )
        else:
            lines.append(
                "- Exposure: external, so priority uses Open. "
                "The internal path (Controlled) is below."
            )
        if risk.get("epss") is None:
            lines.append("- EPSS: n/a")
        else:
            fetched = risk.get("epss_fetched_at")
            extra = f" · fetched {fetched}" if fetched else ""
            lines.append(
                f"- EPSS: {format_epss(risk.get('epss'))} · "
                f"{_source_phrase('first-epss', cve_id)}{extra}"
            )
        if risk.get("note"):
            lines.append(f"- Note: {risk['note']}")
        lines.append(f"- If internal: {risk['trace_internal']}")
        lines.append(f"- If external: {risk['trace_external']}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines).rstrip()
