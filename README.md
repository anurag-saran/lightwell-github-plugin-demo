# Lightwell GitHub Plugin

Plugin that scans a **target app repo** for Lightwell-matching libraries and opens a PR there.

The app repo (e.g. [`payments-service`](https://github.com/anurag-saran/payments-service)) is a normal Maven app — **no** Lightwell plugin code required there. (That app may also host upgrade-delta PaC for live grading; remediations still open from this plugin repo.)

## Contents

- `lightwell-github/` — catalog + scan/apply/badge/sync scripts
- `.github/workflows/lightwell-remediate.yml` — runs here; opens PRs on the target app
- `.github/workflows/lightwell-ci.yml` — unit tests + catalog drift check

## One-time setup

1. Create a **fine-grained PAT** with access to the target app only:
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
| Schedule | Weekly Monday 09:00 UTC (default target `anurag-saran/payments-service`) |

Point shields.io at:

`https://raw.githubusercontent.com/<owner>/<repo>/lightwell/badge/lightwell-badge.json`

## Run against payments-service

1. Open **Actions → Lightwell Remediate → Run workflow**
2. Keep target `anurag-saran/payments-service` (or change it; must be `owner/name`)
3. Optionally enable **dry_run** to scan without push/PR
4. Run — PR opens on the **app** repo (unless dry-run)
5. On the app: review PR → **merge** or **close**

## Scripts

| Script | Role |
|--------|------|
| `scan_poms.py` | Scan POMs → `matches.json` + `report.md` |
| `apply_bumps.py` | Apply version bumps from matches |
| `write_badge.py` | Write shields.io endpoint JSON |
| `sync_catalog.py` | Crawl Lightwell Maven indexes → `catalog.json` (`--check` / `--dry-run`) |

## Local dry-run (against a local clone of the app)

```bash
python3 lightwell-github/scan_poms.py --root /path/to/payments-service
cat lightwell-github/out/report.md
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
