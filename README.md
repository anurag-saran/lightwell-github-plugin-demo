# Lightwell GitHub Plugin

Plugin repo for Dependabot-style Lightwell library remediations on GitHub.

App repos (like [`payments-service`](https://github.com/anurag-saran/payments-service)) stay clean — they only add a thin workflow that **calls** this plugin.

No MTA. No OpenRewrite. Catalog match → pom bump → PR.

## Contents

- `lightwell-github/catalog.json` — Lightwell match catalog
- `lightwell-github/scan_poms.py` / `apply_bumps.py` — scan and apply helpers
- `.github/workflows/lightwell-remediate.yml` — reusable workflow (`workflow_call`)
- `payments-service-demo/` — optional fixture for testing this plugin repo itself

## Use from an app repo

In the app (e.g. `payments-service`), add only:

```yaml
# .github/workflows/lightwell-remediate.yml
name: Lightwell Remediate
on:
  workflow_dispatch:
  push:
    paths: ["**/pom.xml"]
  schedule:
    - cron: "0 9 * * 1"

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  remediate:
    uses: anurag-saran/lightwell-github-plugin-demo/.github/workflows/lightwell-remediate.yml@main
    secrets: inherit
```

App **Settings → Actions**:

1. Allow actions (including reusable workflows from other repos)
2. Workflow permissions: **Read and write**
3. Check **Allow GitHub Actions to create and approve pull requests**

## Behavior

1. Runs on schedule / pom change / manual dispatch
2. Matches app deps against this repo’s catalog
3. Opens or updates a PR labeled `lightwell`
4. Developer **merges** to accept or **closes** to reject

## Local dry-run

```bash
python3 lightwell-github/scan_poms.py --root payments-service-demo
cat lightwell-github/out/report.md
```
