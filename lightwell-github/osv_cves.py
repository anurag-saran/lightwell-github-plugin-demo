#!/usr/bin/env python3
"""Join Lightwell OSV advisories onto remediation matches (CVE IDs + CVSS).

Lightwell publishes OSV docs for remediated builds. Public demo index (anonymous):
  https://packages.redhat.com/api/pulp-content/public-lightwell-demo/osv/java/remediated

Only CVE IDs present in advisory ``aliases`` are returned — never invented.
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_OSV_URL = (
    "https://packages.redhat.com/api/pulp-content/"
    "public-lightwell-demo/osv/java/remediated"
)

_REMEDIATED_RE = re.compile(r"[.-](rhlw|redhat)-\d+", re.I)

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def is_remediated_version(ver: str | None) -> bool:
    return bool(_REMEDIATED_RE.search(ver or ""))


def version_key(v: str | None) -> tuple:
    """Loose semver sort key for comparing OSV fixed vs target builds."""
    parts = re.split(r"[.\-+]", v or "")
    key: list[tuple[int, Any]] = []
    for p in parts:
        key.append((0, int(p)) if p.isdigit() else (1, p))
    return tuple(key)


def version_satisfies_fixed(target: str, fixed: str) -> bool:
    if not target or not fixed:
        return False
    if target == fixed:
        return True
    return version_key(target) >= version_key(fixed)


def round_up_1(n: float) -> float:
    """CVSS 3.1 roundup to one decimal place."""
    return math.ceil(n * 10) / 10.0 if n > 0 else 0.0


def cvss_v3_base_score(vector: str) -> float | None:
    """Parse a CVSS:3.x vector string into a base score, or None if incomplete."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().upper()
        if k.startswith("CVSS"):
            continue
        metrics[k] = v.strip().upper()
    try:
        scope = metrics["S"]
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = (_PR_C if scope == "C" else _PR_U)[metrics["PR"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    return round_up_1(base)


def severity_rating(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def severity_from_osv_doc(doc: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Return (base_score, rating, vector) from an OSV document's severity block."""
    best_score: float | None = None
    best_vector: str | None = None
    for sev in doc.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        vector = sev.get("score")
        if not isinstance(vector, str):
            continue
        score = cvss_v3_base_score(vector)
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score = score
            best_vector = vector
    return best_score, severity_rating(best_score), best_vector


def osv_cve_ids(doc: dict[str, Any]) -> list[str]:
    return sorted(
        {
            a
            for a in (doc.get("aliases") or [])
            if isinstance(a, str) and a.startswith("CVE-")
        }
    )


def osv_fixed_events(doc: dict[str, Any]):
    for aff in doc.get("affected") or []:
        pkg = ((aff.get("package") or {}).get("name")) or ""
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                fixed = ev.get("fixed")
                if pkg and fixed:
                    yield pkg, fixed


def package_matches_gav(osv_pkg: str, group_id: str, artifact_id: str) -> bool:
    gav = f"{group_id}:{artifact_id}"
    if osv_pkg == gav:
        return True
    if osv_pkg == artifact_id or osv_pkg.endswith(":" + artifact_id):
        return True
    return False


def _cache_dir() -> Path:
    override = os.environ.get("LIGHTWELL_OSV_CACHE")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "lightwell-github" / "osv"
    return Path.home() / ".cache" / "lightwell-github" / "osv"


def _http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "lightwell-github-plugin/osv-cves"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_osv_records_from_dir(directory: Path | str | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not directory:
        return records
    path = Path(directory)
    if not path.is_dir():
        return records
    for name in sorted(path.iterdir()):
        if not name.name.endswith(".json") or name.name.startswith("."):
            continue
        try:
            doc = json.loads(name.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"  ! OSV skip {name}: {exc}", flush=True)
            continue
        if isinstance(doc, dict) and doc.get("affected") is not None:
            records.append(doc)
    return records


def fetch_osv_records(base_url: str | None, cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """Fetch OSV advisories from a Lightwell osv/.../remediated index. Failure-tolerant."""
    if not base_url:
        return []
    cache = cache_dir or _cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    base = base_url.rstrip("/")
    records: list[dict[str, Any]] = []
    try:
        names: list[str] = []
        try:
            raw = _http_get(f"{base}/PULP_MANIFEST")
            for line in raw.decode("utf-8", errors="replace").splitlines():
                fname = line.split(",", 1)[0].strip()
                if fname.endswith(".json"):
                    names.append(fname)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            html = _http_get(base + "/").decode("utf-8", errors="replace")
            found = re.findall(r'href="(\./)?(x_RHLW-[^"]+\.json)"', html)
            names = sorted({(n[1] if isinstance(n, tuple) else n) for n in found})
            names = [n[2:] if n.startswith("./") else n for n in names]

        for fname in names:
            if not fname.endswith(".json"):
                continue
            cached = cache / Path(fname).name
            doc = None
            if cached.is_file():
                try:
                    doc = json.loads(cached.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    doc = None
            if doc is None:
                try:
                    body = _http_get(f"{base}/{fname}")
                    cached.write_bytes(body)
                    doc = json.loads(body.decode("utf-8"))
                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    TimeoutError,
                    OSError,
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                ) as exc:
                    print(f"  ! OSV fetch {fname}: {exc}", flush=True)
                    continue
            if isinstance(doc, dict) and doc.get("affected") is not None:
                records.append(doc)
    except Exception as exc:  # noqa: BLE001 — advisory join must never fail the scan
        print(f"  ! OSV index unavailable ({exc}) — continuing without CVE data", flush=True)
        return []
    return records


def load_osv_index(
    *,
    osv_dir: Path | str | None = None,
    osv_url: str | None = DEFAULT_OSV_URL,
    fetch: bool = True,
) -> list[dict[str, Any]]:
    records = load_osv_records_from_dir(osv_dir)
    seen = {r.get("id") for r in records if r.get("id")}
    if fetch and osv_url:
        for r in fetch_osv_records(osv_url):
            rid = r.get("id")
            if rid and rid in seen:
                continue
            records.append(r)
            if rid:
                seen.add(rid)
    return records


def highest_osv_fixed(
    osv_records: list[dict[str, Any]],
    *,
    group_id: str,
    artifact_id: str,
    from_version: str | None = None,
) -> str | None:
    """Highest Lightwell ``fixed`` build for a GAV across OSV advisories.

    When ``from_version`` is set (e.g. ``5.3.18``), only candidates that are
    rebuilds of that upstream base are considered.
    """
    best: str | None = None
    for doc in osv_records:
        for pkg, fixed in osv_fixed_events(doc):
            if not package_matches_gav(pkg, group_id, artifact_id):
                continue
            if not is_remediated_version(fixed):
                continue
            if from_version:
                prefix = f"{from_version}."
                if not (fixed == from_version or fixed.startswith(prefix)):
                    continue
            if best is None or version_key(fixed) > version_key(best):
                best = fixed
    return best


def elevate_to_highest_osv_fixed(
    rows: list[dict[str, Any]],
    osv_records: list[dict[str, Any]],
    *,
    version_key_name: str = "toVersion",
) -> int:
    """Bump each row's target build to the highest OSV ``fixed`` when newer.

    Returns the number of rows whose target version changed. Used so the plugin
    always proposes e.g. ``5.3.18.rhlw-00010`` even if the Maven index still
    lists an older suffix such as ``…-00003``.
    """
    changed = 0
    if not osv_records:
        return 0
    for row in rows:
        current = str(row.get(version_key_name) or "")
        highest = highest_osv_fixed(
            osv_records,
            group_id=str(row.get("groupId") or ""),
            artifact_id=str(row.get("artifactId") or ""),
            from_version=str(row.get("fromVersion") or "") or None,
        )
        if not highest:
            continue
        if not current or version_key(highest) > version_key(current):
            if current != highest:
                row[version_key_name] = highest
                changed += 1
    return changed


def cves_fixed_by_build(
    osv_records: list[dict[str, Any]],
    *,
    group_id: str,
    artifact_id: str,
    version: str,
) -> list[dict[str, Any]]:
    """CVEs a remediated/validated Lightwell build addresses, with CVSS when present."""
    if not is_remediated_version(version) or not osv_records:
        return []
    found: dict[str, dict[str, Any]] = {}
    for doc in osv_records:
        cves = osv_cve_ids(doc)
        if not cves:
            continue
        score, rating, vector = severity_from_osv_doc(doc)
        summary = (doc.get("summary") or doc.get("details") or "")[:240]
        for pkg, fixed in osv_fixed_events(doc):
            if not package_matches_gav(pkg, group_id, artifact_id):
                continue
            if not version_satisfies_fixed(version, fixed):
                continue
            for cve in cves:
                prev = found.get(cve)
                prefer = (
                    prev is None
                    or fixed == version
                    or version_key(fixed)
                    > version_key((prev or {}).get("fixed_in") or "")
                )
                if prefer:
                    entry: dict[str, Any] = {
                        "id": cve,
                        "osv_id": doc.get("id"),
                        "fixed_in": fixed,
                        "summary": summary,
                    }
                    if score is not None:
                        entry["cvss"] = score
                        entry["severity"] = rating
                    if vector:
                        entry["vector"] = vector
                    found[cve] = entry
    return [found[k] for k in sorted(found)]


def attach_cves_to_matches(
    matches: list[dict[str, Any]],
    osv_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Mutate matches in place: elevate target build, add CVEs, sort by severity."""
    elevate_to_highest_osv_fixed(matches, osv_records)
    for m in matches:
        details = cves_fixed_by_build(
            osv_records,
            group_id=m["groupId"],
            artifact_id=m["artifactId"],
            version=m["toVersion"],
        )
        m["cves"] = details
        scores = [d["cvss"] for d in details if d.get("cvss") is not None]
        if scores:
            m["max_cvss"] = max(scores)
            m["max_severity"] = severity_rating(m["max_cvss"])
        else:
            m["max_cvss"] = None
            m["max_severity"] = None

    def sort_key(m: dict[str, Any]):
        score = m.get("max_cvss")
        # None sorts last; higher CVSS first
        return (
            0 if score is not None else 1,
            -(score if score is not None else 0.0),
            m.get("artifactId") or "",
            m.get("groupId") or "",
        )

    matches.sort(key=sort_key)
    return matches


def format_cve_inline(cve: dict[str, Any]) -> str:
    """Human line for one CVE, e.g. ``CVE-2023-20863 (7.5 HIGH)``."""
    parts = [cve["id"]]
    if cve.get("cvss") is not None:
        sev = cve.get("severity") or ""
        parts.append(f"({cve['cvss']} {sev})".strip())
    return " ".join(parts)
