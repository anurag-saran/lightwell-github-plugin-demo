# Lightwell GitHub Plugin

Plugin that scans a **target app repo** for Lightwell-matching libraries and opens a PR there.

## Customer setup

**[GITHUB.md — Lightwell GitHub plugin setup](../lightwell-integrations/GITHUB.md)**  
(in the lightwell-integrations kit: GitHub.com or GHES with Actions)

The remediations catalog is built only from the **public** Lightwell console demos
([java-remediated-demo](https://console.redhat.com/lightwell/demo/java-remediated-demo),
[java-validated-demo](https://console.redhat.com/lightwell/demo/java-validated-demo)) via the
unauthenticated `public-lightwell-demo` Maven feeds. Refresh with `sync_catalog.py`.

The app repos are normal Maven apps — **no** Lightwell plugin code required there
(they may also host upgrade-delta PaC for live grading; remediations still open from
**this** plugin repo):

| Target app | Role |
|---|---|
| [`payments-service`](https://github.com/anurag-saran/payments-service) | Live grade **B** (jackson drop-in) |
| [`payments-service-notests`](https://github.com/anurag-saran/payments-service-notests) | REACHABILITY_ONLY |
| [`payments-service-grade-c`](https://github.com/anurag-saran/payments-service-grade-c) | Live grade **C** |
| [`payments-service-grade-f`](https://github.com/anurag-saran/payments-service-grade-f) | Live grade **F** |

Each app should include [`.github/workflows/lightwell-badge-sync.yml`](samples/lightwell-badge-sync.yml)
(checks out this plugin for scan/badge helpers). After a remediation PR merges — or any
`pom.xml` change on `main` — that workflow re-scans and republishes the shields count.

## Contents

- `lightwell-github/` — catalog + scan/apply/badge/sync scripts
- `.github/workflows/lightwell-remediate.yml` — runs here; opens PRs on the target app
- `.github/workflows/lightwell-ci.yml` — unit tests + catalog drift check

## One-time setup

1. Create a **fine-grained PAT** with access to **all four** payment app repos:
   - **Contents:** Read and write
   - **Pull requests:** Read and write
   - (Classic `repo` scope works but is broader than needed.)
2. In this plugin repo: **Settings → Secrets and variables → Actions** → add `LIGHTWELL_REPO_TOKEN`
3. **Settings → Actions**: allow actions; workflow uses `gh auth setup-git` (token is not embedded in the git remote URL)

## Behavior

| What | Where |
|------|--------|
| Remediation PR | Branch `lightwell/remediations` on the **target** app (`--force-with-lease`) |
| Available-updates badge | Branch `lightwell/badge` on the **target** app (never commits to `main`) |
| After pom merge | Target app workflow **Lightwell badge sync** (on `pom.xml` change) refreshes the count |
| Schedule | Weekly Monday 09:00 UTC — **all four** payment apps |
| Manual | Actions → Lightwell Remediate → pick one of the four targets |

Point shields.io at:

`https://raw.githubusercontent.com/<owner>/<repo>/lightwell/badge/lightwell-badge.json`

## Run against a payment app

1. Open **Actions → Lightwell Remediate → Run workflow**
2. Pick a target (`payments-service`, `-notests`, `-grade-c`, or `-grade-f`)
3. Optionally enable **dry_run** to scan without push/PR
4. Run — PR opens on the **app** repo (unless dry-run)
5. On the app: review PR → **merge** or **close**
6. After merge, the app’s **Lightwell badge sync** workflow runs automatically and
   updates the README badge (no second manual plugin run)

Schedule and catalog pushes remediate **all four** targets in parallel.

### Install badge sync on a new app

```bash
mkdir -p /path/to/app/.github/workflows
cp samples/lightwell-badge-sync.yml /path/to/app/.github/workflows/
# Edit repository: if you forked this plugin
```

## Scripts

| Script | Role |
|--------|------|
| `scan_poms.py` | Scan POMs → `matches.json`, `report.md`, and `pr-body.md` (OSV CVEs plus SSVC priority) |
| `ssvc_risk.py` | Look up CERT/CC SSVC outcomes from the vendored deployer table |
| `osv_cves.py` | Fetch/load Lightwell OSV advisories; CVSS 3.1 base score; attach to matches |
| `apply_bumps.py` | Apply version bumps from matches |
| `write_badge.py` | Write shields.io endpoint JSON |
| `sync_catalog.py` | Crawl Lightwell Maven indexes → `catalog.json` (`--check` / `--dry-run`) |

## Local dry-run (against a local clone of the app)

```bash
python3 lightwell-github/scan_poms.py --root /path/to/payments-service \
  --risk-config targets/payments-service.lightwell-risk.json
cat lightwell-github/out/report.md
```

Offline CVE join (no network), using a local OSV mirror:

```bash
python3 lightwell-github/scan_poms.py --root /path/to/app \
  --osv-dir /path/to/osv --offline
```

Skip CVE enrichment entirely: add `--no-osv`.

The remediation PR / `report.md` lists each bump with **CVEs fixed** and **CVSS**
severity (from Lightwell OSV), then an SSVC priority table. Matches are ordered by
external outcome, then internal outcome, then EPSS, then CVSS. A match with no CVEs
sorts last. `--no-risk` leaves the CVSS ordering from the OSV join.

## SSVC priority

The priority table is the CERT/CC deployer decision table
`deployer_patch_application_priority_1_0_0`, vendored at
`lightwell-github/ssvc/deployer_patch_application_priority_1_0_0.csv`
(commit `bf3213bc0bd2bf3cf1329c9b48f72d7163a682b1`). Outcomes are looked up from
that file. They are not reimplemented in Python.

| Column | Meaning |
|--------|---------|
| CVE | Advisory fixed by the Lightwell build |
| Library (current → Lightwell build) | Dependency the scan matched |
| CVSS | Base score from Lightwell OSV. Kept alongside SSVC |
| Exploitation | None, Public PoC, or Active |
| Automatable | No or Yes |
| App impact | SSVC Human Impact for this application |
| If the app is internal | Colored outcome when System Exposure is Controlled |
| If the app is external | Colored outcome when System Exposure is Open |
| EPSS | FIRST exploit probability, display and tie-break only. Missing is `n/a` |

Both exposure columns are always computed. The scan does not ask which one you are.
A config `exposure` of `internal` or `external` marks that column `(declared)` and
still fills the other column.

Under the table, a color key lists the four outcomes: Immediate (red),
Out-of-Cycle (orange), Scheduled (amber), and Defer (green).

### Sources and fallbacks

| Decision point | Source | If missing |
|----------------|--------|------------|
| Exploitation | CISA KEV, else the CISA ADP SSVC block on the CVE record | Public PoC, marked `(assumed)` |
| Automatable | CISA ADP SSVC block | Yes, marked `(assumed)` |
| Human Impact | `.lightwell-risk.json` in the target repo, else `--risk-config` | Medium, marked `(assumed)` |
| EPSS | `https://api.first.org/data/v1/epss` in batches of at most 100 CVEs | stored as `null`, shown as `n/a` |

A CVE in the KEV catalog is Exploitation = Active. Vulnrichment tokens map as
`poc` → Public PoC, and `none`, `active`, `yes`, and `no` pass through. Any other
token counts as missing and uses the fallback. Missing data never lowers urgency.
A feed outage logs a warning, uses the cache under `lightwell-github/out/feeds/`
when it exists, and otherwise uses the same fallbacks. `--offline` reads that cache
and does not call the feeds. `--no-risk` skips the section. The run still produces
`matches.json` and `report.md`.

The report header includes the feed date, the table version, and
`SSVC data found for X of Y CVEs; Z values assumed.` Older CVEs often have no CISA
ADP record, so many values are assumed.

Under the table, each CVE has a `How this was computed` trace: every input with its
value, source, and fetch date, then both decision paths.

### Config

The target repo can carry `.lightwell-risk.json`:

```json
{
  "human_impact": "High",
  "exposure": "external",
  "overrides": {
    "CVE-2024-0000": {
      "exploitation": "Active",
      "automatable": "No",
      "note": "Mythos finding #123"
    }
  }
}
```

`human_impact` is `Low`, `Medium`, `High`, or `Very High`. Overrides replace the
fetched value and are labeled customer-provided, with the note in the trace. An
invalid field is ignored and a warning is printed. The other fields still apply.

`--risk-config <path>` is used only when the target has no `.lightwell-risk.json`.
Demo configs for apps we do not edit live in `targets/`.
`targets/payments-service.lightwell-risk.json` sets Human Impact to High, and the
report shows that as `High (demo setting)`. With every other input at its default
(Public PoC, Yes, Medium) both exposure columns are Scheduled, so the demo config
is what makes the two columns differ.

`scan_poms.py` also writes `pr-body.md`. If that body would pass 65,536 characters,
the computation traces are dropped and the body links to `report.md`. The remediate
workflow opens the PR from that file.

Target builds use the **highest published** `.rhlw-NNNN` (or `.redhat-NNNN`) for
that upstream version: `sync_catalog.py` takes the max from the Maven index, then
elevates to a newer OSV `fixed` **only if that artifact resolves** from the public
Lightwell Maven demo. If OSV cites a later build that is not published yet
(e.g. Maven has `5.3.18.rhlw-00003` but OSV says `5.3.18.rhlw-00010`), the catalog
and PR keep the published build and note the later OSV fix (with its CVEs).
Scan-time enrichment uses the same hybrid rule.

When you run an older upstream than Lightwell services (e.g. snakeyaml `1.30` while
the catalog has `1.33.0.rhlw-00001`), the **Proposed bumps** table lists it as
**Serviced — at a different version** with CVEs for the serviced build. Those rows
are informational only (not auto-applied to the pom).

## Tests

```bash
python3 -m unittest discover -s tests -v
```
