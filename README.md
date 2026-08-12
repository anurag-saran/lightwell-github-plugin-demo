# Lightwell GitHub Plugin

Plugin that scans a **target app repo** for Lightwell-matching libraries and opens a PR there.

The app repo (e.g. [`payments-service`](https://github.com/anurag-saran/payments-service)) stays a normal Maven app — **no** `.github/workflows` and **no** plugin code required in the app.

## Contents

- `lightwell-github/` — catalog + scan/apply scripts
- `.github/workflows/lightwell-remediate.yml` — runs here; opens PRs on the target app
## One-time setup

1. Create a PAT (classic `repo` scope, or fine-grained with contents/PRs on the target app).
2. In this plugin repo: **Settings → Secrets and variables → Actions** → add `LIGHTWELL_REPO_TOKEN`
3. **Settings → Actions**: allow actions; workflow can use the secret to push to the app repo

## Run against payments-service

1. Open **Actions → Lightwell Remediate → Run workflow**
2. Keep target `anurag-saran/payments-service` (or change it)
3. Run — PR opens on the **app** repo
4. On the app: review PR → **merge** or **close**

Also runs weekly on schedule (same default target).

## Local dry-run (against a local clone of the app)

```bash
python3 lightwell-github/scan_poms.py --root /path/to/payments-service
cat lightwell-github/out/report.md
```
