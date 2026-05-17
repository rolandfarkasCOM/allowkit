# db-reset.ps1 — nuke local Miniflare D1 state, replay migrations, verify.
#
# Use when wrangler-dev complains about missing tables, or when you want a
# clean slate after migration churn.
#
# Run with wrangler dev STOPPED first, then:
#   npm run db:reset:local
# After it finishes:
#   npm run dev

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$d1Path = Join-Path $root '.wrangler\state\v3\d1'
$migrationsDir = Join-Path $root 'migrations'

if (-not (Test-Path $migrationsDir)) {
  Write-Host "[db-reset] migrations directory missing: $migrationsDir" -ForegroundColor Red
  exit 1
}

if (Test-Path $d1Path) {
  Write-Host "[db-reset] removing local D1 state at $d1Path" -ForegroundColor Cyan
  Remove-Item -Recurse -Force $d1Path
} else {
  Write-Host "[db-reset] no existing local D1 state, nothing to remove" -ForegroundColor DarkGray
}

# Replay every migration file in order via "d1 execute --file" — same path
# wrangler-dev reads from, so the schema actually shows up in dev.
$files = Get-ChildItem -Path $migrationsDir -Filter '*.sql' | Sort-Object Name
foreach ($f in $files) {
  Write-Host ("[db-reset] applying " + $f.Name + "...") -ForegroundColor Cyan
  # Quote the --file= arg so PowerShell doesn't split it into two tokens.
  $relPath = "migrations/" + $f.Name
  npx wrangler d1 execute allowkit_audit --local "--file=$relPath"
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("[db-reset] execute failed on " + $f.Name) -ForegroundColor Red
    exit 1
  }
}

# Verify expected objects (table + indexes + append-only triggers).
Write-Host "[db-reset] verifying schema..." -ForegroundColor Cyan
$verifyOutput = npx wrangler d1 execute allowkit_audit --local --command "SELECT name FROM sqlite_master WHERE type IN ('table','index','trigger') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name" --json 2>&1
$rendered = $verifyOutput -join "`n"
$matches = [regex]::Matches($rendered, '"name":\s*"([a-z0-9_]+)"')
$found = @()
foreach ($m in $matches) { $found += $m.Groups[1].Value }
$found = $found | Sort-Object -Unique

$expected = @(
  'consent_audit',
  'consent_audit_no_delete',
  'consent_audit_no_update',
  'idx_audit_app',
  'idx_audit_subject'
)
$missing = @($expected | Where-Object { $_ -notin $found })

if ($missing.Count -gt 0) {
  Write-Host ("[db-reset] MISSING: " + ($missing -join ', ')) -ForegroundColor Red
  Write-Host ("[db-reset] Found: " + ($found -join ', ')) -ForegroundColor Yellow
  exit 1
}

Write-Host ("[db-reset] all " + $expected.Count + " objects present.") -ForegroundColor Green
Write-Host "[db-reset] start the worker: npm run dev" -ForegroundColor Green
