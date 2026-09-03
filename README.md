# Lightwell GitHub Plugin

Plugin that scans a **target app repo** for Lightwell-matching libraries and opens a PR there.

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

Each app's `.github/workflows/lightwell-badge-sync.yml` checks out
[`anurag-saran/lightwell-github-plugin-demo`](https://github.com/anurag-saran/lightwell-github-plugin-demo)
for scan/badge helpers.

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

Schedule and catalog pushes remediate **all four** targets in parallel.

## Scripts

| Script | Role |
|--------|------|
| `scan_poms.py` | Scan POMs → `matches.json` + `report.md` (joins Lightwell OSV for CVE + CVSS) |
| `osv_cves.py` | Fetch/load Lightwell OSV advisories; CVSS 3.1 base score; attach to matches |
| `apply_bumps.py` | Apply version bumps from matches |
| `write_badge.py` | Write shields.io endpoint JSON |
| `sync_catalog.py` | Crawl Lightwell Maven indexes → `catalog.json` (`--check` / `--dry-run`) |

## Local dry-run (against a local clone of the app)

```bash
python3 lightwell-github/scan_poms.py --root /path/to/payments-service
cat lightwell-github/out/report.md
```

Offline CVE join (no network), using a local OSV mirror:

```bash
python3 lightwell-github/scan_poms.py --root /path/to/app \
  --osv-dir /path/to/osv --offline
```

Skip CVE enrichment entirely: add `--no-osv`.

The remediation PR / `report.md` lists each bump with **CVEs fixed** and **CVSS**
severity (from Lightwell OSV). Matches are sorted highest severity first.

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
