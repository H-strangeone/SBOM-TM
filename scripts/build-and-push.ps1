<#
.SYNOPSIS
Builds the Docker image locally and pushes to GHCR.
#>

param(
    [string]$Tag = "latest",
    [string]$Image = ""
)

# --- Resolve image name (force lowercase for GHCR) ---
if ([string]::IsNullOrEmpty($Image)) {
    if ($env:GHCR_USERNAME) {
        $repoUser = $env:GHCR_USERNAME.ToLower()
        $Image = "ghcr.io/$repoUser/sbom-tm"
    } else {
        Write-Host "GHCR_USERNAME not set. Using system username."
        $repoUser = $env:USERNAME.ToLower()
        $Image = "ghcr.io/$repoUser/sbom-tm"
    }
}

# --- Checks ---
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker CLI not found. Install Docker and ensure it's in PATH."
    exit 2
}

if (-not $env:GHCR_PAT) {
    Write-Error "Set env var GHCR_PAT with packages:write permission."
    exit 3
}

$fullTag = "${Image}:${Tag}"
Write-Host "Building image: $fullTag"
docker build -t $fullTag -f ./Dockerfile .

# --- Verify PAT scopes via GitHub API ---
Write-Host "Verifying GHCR PAT scopes and owner match..."
try {
    $headers = @{ Authorization = "token $env:GHCR_PAT"; 'User-Agent' = 'sbom-tm-ghcr-check' }
    $resp = Invoke-WebRequest -Uri 'https://api.github.com/user' -Headers $headers -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Failed to call GitHub API to validate PAT: $($_.Exception.Message)"
    exit 4
}

try {
    $json = $resp.Content | ConvertFrom-Json
    $tokenLogin = $json.login
} catch {
    Write-Warning "Unable to parse GitHub API response; continuing but login check skipped."
    $tokenLogin = $null
}

$scopes = $resp.Headers['x-oauth-scopes'] -join ', '
if (-not ($scopes -match 'write:packages')) {
    Write-Error "GHCR PAT does not include 'write:packages'. Create a PAT with 'write:packages' (and 'read:packages') or a fine-grained token with Packages=Read & write. Scopes: $scopes"
    exit 5
}

if ($tokenLogin -and $tokenLogin.ToLower() -ne $repoUser.ToLower()) {
    Write-Warning "The token owner ($tokenLogin) does not match GHCR_USERNAME ($repoUser). You may still push to an org, but ensure permissions are correct."
}

# --- Login (use password-stdin) ---
Write-Host "Logging into ghcr.io as $repoUser"
echo $env:GHCR_PAT | docker login ghcr.io -u $repoUser --password-stdin

# --- Push Version Tag ---
Write-Host "Pushing $fullTag"
docker push $fullTag

# --- Push Latest Tag ---
Write-Host "Tagging & pushing latest"
docker tag $fullTag "${Image}:latest"
docker push "${Image}:latest"

Write-Host "Done."
