# Lightwell GitHub Plugin Demo

GitHub-only demo: scan a Maven app for Lightwell-matching libraries, show the developer what will change, then open a PR only after they press a button.

No MTA. No OpenRewrite. Catalog match → pom bump → PR.

## What it proves

1. A GitHub Action can detect deps that have a Lightwell remediated version (e.g. `commons-io:2.11.0` → `2.11.0.rhlw-00001`).
2. The developer sees the proposed change **before** any PR exists (Job Summary + Issue).
3. The developer explicitly runs **Lightwell Open PR** (`confirm=open-pr`) to create the pull request.

## Repo layout

- `payments-service-demo/` — sample Maven app (baseline uses `commons-io:2.11.0`)
- `lightwell-github/catalog.json` — static Lightwell match catalog
- `lightwell-github/scan_poms.py` — scan only (writes report, no edits)
- `lightwell-github/apply_bumps.py` — apply version bumps from scan output
- `.github/workflows/lightwell-scan.yml` — scan → Job Summary + Issue
- `.github/workflows/lightwell-open-pr.yml` — button → branch + PR

## Demo flow on GitHub

### Step 1 — Scan (info only)

1. Open **Actions** → **Lightwell Scan** → **Run workflow**
2. Read the **Job Summary**, or open the Issue titled **Lightwell remediations available**

You should see:

```diff
-            <version>2.11.0</version>
+            <version>2.11.0.rhlw-00001</version>
```

No PR is opened yet.

### Step 2 — Open PR (button)

1. Review the scan info
2. **Actions** → **Lightwell Open PR** → **Run workflow**
3. Set `confirm` to `open-pr`
4. Run — opens a PR with the pom bump

## Local dry-run

```bash
python3 lightwell-github/scan_poms.py --root .
cat lightwell-github/out/report.md

# optional: apply locally (does not open a PR)
python3 lightwell-github/apply_bumps.py --root .
git diff -- payments-service-demo/pom.xml
git checkout -- payments-service-demo/pom.xml
```

## Reset baseline

After a successful Open PR merge (or local apply), set the demo app back to:

```xml
<version>2.11.0</version>
```

in `payments-service-demo/pom.xml` before re-running the scan demo.
