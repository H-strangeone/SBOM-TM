SBOM-TM
=======

SBOM-TM is a small tool for SBOM-based threat modelling and CI enforcement.

Quick: make it a GitHub Action
------------------------------
This repository ships a lightweight composite GitHub Action and example workflows so projects can run SBOM-TM in CI and post a sticky PR comment with findings (like Dependabot).

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

Usage (as a GitHub Action)
-------------------------
There are two ways to use the action:

- Use the action in this repository directly (recommended for testing):

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SBOM-TM
        uses: ./
        with:
          command: diff
          args: --git
          project: ${{ github.sha }}
```

- Use a published action (after release / marketplace listing):

```yaml
- name: Run SBOM-TM
  uses: <owner>/SBOM-TM@v1
  with:
    command: diff
    args: --git
    project: ${{ github.sha }}
```

Container action (recommended for CI speed)
------------------------------------------
This repository also contains a `Dockerfile` and the action is defined as a container action. When published, the action will run from a prebuilt image on GHCR for faster startup.

Local usage (the runner will build the container automatically):

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run sbom-tm (container action)
        uses: ./
        with:
          command: diff
          args: --git
          project: ${{ github.sha }}
```

To publish the prebuilt image to GHCR (the included workflow does this on tag), push a tag like `v1.0.0` and the workflow will build and push `ghcr.io/<owner>/sbom-tm:v1.0.0` and `:latest`.

Example CI workflow
-------------------
See `.github/workflows/sbom-security.yml` in this repository — it runs `sbom-tm diff --git`, uploads the markdown report as an artifact, and posts it as a sticky PR comment using `marocchino/sticky-pull-request-comment@v2`.

Publishing a Docker image to GHCR
--------------------------------
A workflow `.github/workflows/publish-ghcr.yml` is included that builds and publishes a multi-platform image to GHCR when you push a tag like `v1.2.3`.

Next steps to make this production-ready
---------------------------------------
- Publish a GitHub release and tag (GHCR publishing requires proper permissions).
- Optionally convert the action into a container action that references a pre-built image for faster runs.
- Improve Markdown output (inline annotations, check-run summaries).

If you want, I can (pick one):
- Publish the action container + create a release PR that updates the `uses:` references, or
- Convert the composite action to a container action and add a small entrypoint image, or
- Improve the PR comment to include inline file annotations and suggested fixes.

Build & publish (GHCR)
----------------------

Local build and push (PowerShell):

```powershell
# set these env vars first
$env:GHCR_USERNAME = 'your-gh-username'
$env:GHCR_PAT = 'ghp_...'
# build and push a tagged image, script will also push :latest
.\scripts\build-and-push.ps1 -Tag v1.0.0
```

CI release workflow (automated):

- A workflow `.github/workflows/release-publish-and-update-action.yml` is included that builds and publishes the container image to GHCR when you push a tag matching `v*`.
- The workflow expects two repository secrets:
  - `GHCR_PAT` — a Personal Access Token (or GitHub Packages token) that has `packages:write` permission for pushing to GHCR.
  - `PERSONAL_TOKEN` — a PAT with `repo` and `pull_request` permissions used to create the release branch / PR that updates `action.yml` to reference the published image.

Notes and next steps:
- I cannot push images to GHCR from here — you must run the local script or push a tag in this repository so the release workflow runs on GitHub.
- After a tag is pushed and the workflow completes, you can update `action.yml` in a release branch to reference `ghcr.io/${{ github.repository_owner }}/sbom-tm:<tag>` (the release workflow can open a PR for that automatically).
  
Note: the release workflow uses the repository owner value when publishing (so images are pushed to `ghcr.io/${{ github.repository_owner }}/sbom-tm`). If you're running the workflow from your fork or repo under `H-strangeone`, it will publish under your account automatically.
- If you'd like, I can also create a small workflow to automatically tag releases from PR merges (CD pipeline).

