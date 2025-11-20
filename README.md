SBOM-TM — Automated SBOM Security Scanner & Threat Modeler


********************************************************

SBOM-TM is a GitHub Action–powered security tool that scans your project for:


software components

vulnerabilities (via Trivy)

dependency changes

upgrade/downgrade risks

threat-rule violations

*******************************************************


It automatically generates:


SBOM scan reports (JSON / HTML / Markdown)

Diff reports for pull requests

PR comments showing threats if any

Automatic Security Issues when new risks are detected

*********************************************************

What SBOM-TM Does


Builds a CycloneDX SBOM using Syft

Scans it using Trivy for vulnerabilities

Applies threat rules to determine high-risk components

Posts a report on your PR

Raises a GitHub Issue if your main branch contains vulnerabilities

Uploads scan results as GitHub Artifacts


*********************************************************

Why Use It


SBOM-TM gives you automated “Dependabot-style” security alerts but for everything in your project, not just package updates.

This means you get:

better visibility

automated security workflows

consistent scan results

no manual review needed

and also just because 

*********************************************

How to use?


its given below but remember

Add this to .github/workflows/sbom.yml:

uses: h-strangeone/SBOM-TM@v(whatever version is the latest one so if z.x.y is latest put z.x.y after this v no spaces)


***********************************************


Outputs


After each scan you get:

scan_report.md

scan_report.json

scan_report.html

diff_report.md (for PRs)

raises security issue if vulnerabilities found in the issues section





if you are using this then in your workflow add these two file  

1. put it in the root and create .github/workflows/sbom.yml

***********************************************************
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


2. add sbom-issue.yml in the same workflow folder

*************************************************************
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
        uses: h-strangeone/SBOM-TM@v0.4.73
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



************************************************

you can add an ignore list sbom-ci.yml if you want based on your requirements

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

