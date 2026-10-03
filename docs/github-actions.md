# Scanning from GitHub Actions

`jet cloud` runs a scan on the hosted platform from CI: it starts the scan,
waits for it, prints or saves the results, and can fail the job when a finding
is severe enough. With `--format sarif` the findings show up in your
repository's **Security → Code scanning** tab.

## 1. One-time setup

1. In the dashboard, add your site and verify that you own it (full checks
   only run on verified sites).
2. Create an API key under **Settings → API keys**. It's shown once.
3. In your GitHub repository, open **Settings → Secrets and variables →
   Actions** and add:
   - a **secret** `CAULK_API_KEY` with the key,
   - a **variable** `CAULK_API_URL` with the platform's API address.

## 2. The workflow

Save as `.github/workflows/security-scan.yml` and replace `example.com` with
your site:

```yaml
name: Security scan

on:
  schedule:
    - cron: "0 6 * * 1"     # every Monday at 06:00 UTC
  workflow_dispatch:        # and on demand from the Actions tab

permissions:
  contents: read
  security-events: write    # upload results to the Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with:
          python-version: "3.13"

      # Pin a commit (or a release) instead of a branch so the job doesn't
      # change under you.
      - run: pip install "jetscanner @ https://github.com/wesssso512/Jet-Vuln-Scanner/archive/refs/heads/V2.zip"

      - name: Scan
        env:
          CAULK_API_KEY: ${{ secrets.CAULK_API_KEY }}
          CAULK_API_URL: ${{ vars.CAULK_API_URL }}
        run: jet cloud scan example.com --format sarif --output caulk.sarif --fail-on high

      - name: Upload results to the Security tab
        if: always() && hashFiles('caulk.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: caulk.sarif
```

The scan step fails the job when there's a **high** or **critical** finding.
The upload step still runs, so you can see what was found.

## Options

| Option | Default | |
|---|---|---|
| `--checks` | `full` | `quick` (only what any visitor can see; works before verification), `full`, or module keys like `tech,dir` |
| `--format` | `text` | `text`, `json` or `sarif` |
| `--output FILE` | stdout | write the result to a file |
| `--fail-on SEVERITY` | off | exit 1 if a finding is at least `info`, `low`, `medium`, `high` or `critical` |
| `--timeout MINUTES` | `30` | stop waiting; the scan keeps running on the platform |
| `-q` | off | no progress on stderr |

Exit codes: `0` finished · `1` a finding met `--fail-on` · `2` an error (bad
key, unknown or unverified site, failed scan, timeout) with the reason on
stderr · `130` interrupted.

## Good to know

- One scan runs at a time per account. If another one is running, the job
  fails with its id; schedule jobs so they don't overlap.
- A key can only list sites, start scans and read results. It can't add or
  remove sites or change your account, so a leaked CI key does limited
  damage. Revoke it in the dashboard and it stops working at once.
- Scanning after every push is usually too often: a weekly schedule plus a run
  after each deploy is a good start.
