#Requires -Version 5.1
<#
.SYNOPSIS
    Backs up every Conditional Access policy in a tenant to JSON files (read-only).

.DESCRIPTION
    Run this before importing the library or before changing any policy, so you can compare
    and restore. Each policy is saved as its own JSON file, plus a summary CSV.

.EXAMPLE
    .\Export-CAPolicies.ps1 -OutputPath .\backup

.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
    Scope  : Policy.Read.All
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) ("CA-Backup-" + (Get-Date -Format 'yyyyMMdd-HHmm'))),
    [string]$TenantId,
    [switch]$UseExistingConnection
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication is required: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
if (-not $UseExistingConnection) {
    $p = @{ Scopes = 'Policy.Read.All'; NoWelcome = $true }
    if ($TenantId) { $p.TenantId = $TenantId }
    Connect-MgGraph @p
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$all = @()
$next = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
while ($next) {
    $r = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
    $all += @($r.value)
    $next = $r.'@odata.nextLink'
}

foreach ($pol in $all) {
    $safe = ($pol.displayName -replace '[^A-Za-z0-9 _-]', '').Trim() -replace '\s+', '-'
    if (-not $safe) { $safe = $pol.id }
    $pol | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $OutputPath "$safe.json") -Encoding UTF8
}
$all | Select-Object displayName, state, id, createdDateTime, modifiedDateTime |
    Export-Csv -Path (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "  Exported $($all.Count) Conditional Access policies to $OutputPath" -ForegroundColor Green
Write-Host ''
