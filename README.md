
# SBOM-TM  
### Automated SBOM Security Scanner & Threat Modeler
### (how to use this is way down so you can skip to that but if you want to know whats happening please continue)

SBOM-TM is a **GitHub Action–based security tool** that automatically scans your repository for **software supply-chain risks** using a Software Bill of Materials (SBOM).

It provides **Dependabot-style security visibility**, but for *everything* in your project — not just dependency updates.


Features

SBOM-TM scans your project for:

- Software components  
- Known vulnerabilities (via **Trivy**)  
- Dependency additions, removals, and version changes  
- Upgrade / downgrade risks  
- Threat-rule violations  

It automatically generates:

- SBOM scan reports (Markdown / JSON / HTML)  
- SBOM diff reports for Pull Requests  
- Sticky PR comments highlighting new risks  
- GitHub Issues when vulnerabilities exist on `main`  
- GitHub Artifacts containing all reports  

---

##  How It Works

1. Generates a **CycloneDX SBOM** using **Syft**
2. Scans the SBOM using **Trivy**
3. Applies threat-modeling rules
4. Posts results on Pull Requests
5. Fails the workflow if blocking issues are found
6. Raises or updates GitHub Issues for persistent risks

---

##  Outputs

Each run produces:

- `scan_report.md`
- `scan_report.json`
- `scan_report.html`
- `diff_report.md` (Pull Requests only)

Reports are uploaded as **GitHub Artifacts**.

---

## Why Use It

well you get:

- better visibility
- automated security workflows
- consistent scan results
- no manual review needed
  
- and also just because 

##  Installation & Usage

### 1️. Add the Workflow

Create the following files in your repository:


1.`.github/workflows/sbom.yml`

```yaml
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
        uses: h-strangeone/SBOM-TM@v0.4.74
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
        uses: h-strangeone/SBOM-TM@v0.4.74
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
          echo "PWD=$(pwd)"
          echo "--- ls ---"
          ls -R .
          FILE=$(ls sbom-report/*_sbom_diff.md 2>/dev/null || true)
          if [ -n "$FILE" ]; then
            echo "found=true" >> "$GITHUB_OUTPUT"
            echo "path=$FILE" >> "$GITHUB_OUTPUT"
            echo "Found diff markdown at: $FILE"
          else
            echo "found=false" >> "$GITHUB_OUTPUT"
            echo "No diff markdown found."
          fi
      - name: Post Sticky PR Comment
        if: github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          recreate: true
          path: ${{ steps.find_md.outputs.path }}
          message: |
            ## SBOM Diff Report
            {% if steps.find_md.outputs.found == 'true' %}
            See attached SBOM diff report   
            `${{ steps.find_md.outputs.path }}`
            {% else %}
            ❗ No SBOM diff report was generated.
            This may mean:
            - No vulnerabilities were introduced  
            - SBOM generation failed  
            - Diff exited early  
            {% endif %}
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
```




2.`.github/workflows/sbom-issue.yml`

```yaml
name: SBOM-TM Auto Issue

on:
  push:
    branches: [main]

permissions:
  contents: read
  issues: write

jobs:
  create_issue:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SBOM Scan
        id: scan
        uses: h-strangeone/SBOM-TM@v0.4.74
        with:
          mode: scan
          project: demo
      - name: Find Scan Markdown
        id: find_md
        run: |
          FILE=$(ls sbom-report/*_scan_report.md 2>/dev/null || true)
          if [ -n "$FILE" ]; then
            echo "path=$FILE" >> $GITHUB_OUTPUT
            echo "found=true" >> $GITHUB_OUTPUT
          else
            echo "found=false" >> $GITHUB_OUTPUT
          fi
      - name: Create or Update Security Issue
        if: steps.find_md.outputs.found == 'true'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require("fs");
            const path = "${{ steps.find_md.outputs.path }}";
            const body = fs.readFileSync(path, "utf8");
            const title = " SBOM-TM Security Alert";
            const { data: issues } = await github.rest.issues.listForRepo({
              owner: context.repo.owner,
              repo: context.repo.repo,
              labels: "security"
            });
            const existing = issues.find(i => i.title === title);
            if (existing) {
              await github.rest.issues.update({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: existing.number,
                body
              });
            } else {
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title,
                body,
                labels: ["security"]
              });
            }

---






