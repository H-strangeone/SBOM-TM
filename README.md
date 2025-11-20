Usage (local)
-------------
Install locally and run the CLI:

```powershell
python -m pip install --upgrade pip
pip install .
# diff current HEAD with base
sbom-tm diff --git --project LOCAL_TEST
# run a scan
sbom-tm scan --path . --project LOCAL_TEST
```


if you are using this then in your workflow add this sbom.yml

name: SBOM-TM Security Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    name: SBOM Threat Model Scan

    steps:
      # Checkout with full history for diff
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # ===========================
      #          SCAN
      # ===========================
      - name: SBOM-TM Scan
        id: sbom_scan
        uses: h-strangeone/SBOM-TM@v0.4.72
        with:
          mode: scan
          project: demo

      # Save scan report directory
      - name: Upload Scan Report
        uses: actions/upload-artifact@v4
        with:
          name: sbom-scan-report
          path: sbom-report/
          if-no-files-found: warn

      # ===========================
      #          DIFF (PR ONLY)
      # ===========================
      - name: SBOM-TM Diff
        id: sbom_diff
        if: github.event_name == 'pull_request'
        uses: h-strangeone/SBOM-TM@v0.4.72
        with:
          mode: diff
          project: demo

      - name: Upload Diff Report
        if: github.event_name == 'pull_request'
        uses: actions/upload-artifact@v4
        with:
          name: sbom-diff-report
          path: sbom-report/
          if-no-files-found: warn

      # ===========================
      #      STICKY PR COMMENT
      # ===========================
      - name: Find Diff Markdown
        if: github.event_name == 'pull_request'
        id: find_md
        run: |
          FILE=$(ls sbom-report/*_sbom_diff.md 2>/dev/null || true)
          if [ -n "$FILE" ]; then
            echo "found=true" >> "$GITHUB_OUTPUT"
            echo "path=$FILE" >> "$GITHUB_OUTPUT"
          else
            echo "found=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Post Sticky PR Comment
        if: github.event_name == 'pull_request' && steps.find_md.outputs.found == 'true'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          recreate: true
          path: ${{ steps.find_md.outputs.path }}

      # ===========================
      #      PASS / FAIL STATUS
      # ===========================
      - name: Fail if scan failed
        if: steps.sbom_scan.outcome == 'failure'
        run: |
          echo "❌ SBOM-TM found blocking issues."
          exit 1

      - name: Success
        if: steps.sbom_scan.outcome == 'success'
        run: echo "✔ SBOM-TM scan succeeded!"


you can add an ignore list sbom-ci.yml

ignore_cves:
  - CVE-2018-1000656
  - CVE-2019-1010083
  - CVE-2023-30861
  - CVE-2018-18074
  - CVE-2023-32681
  - CVE-2024-35195
  - CVE-2024-47081

ignore_packages:
  - flask
  - requests

fail_on_severities: []
fail_on_rule_categories: []
min_threat_score: 999
