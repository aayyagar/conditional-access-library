#Requires -Version 5.1
<#
.SYNOPSIS
    Imports the Conditional Access Policy Library into a Microsoft Entra ID tenant, in report-only mode by default.

.DESCRIPTION
    Reads policy JSON files from .\policies, fills in your break-glass group, and creates each policy
    through Microsoft Graph. Policies that already exist with the same display name are skipped, so the
    script is safe to run more than once.

    Safety features
      - Report-only by default. Policies log what they WOULD do without blocking anyone.
      - Break-glass group is required and verified to exist before anything is created.
      - -WhatIf connects and reads your tenant, then lists what would be created without creating anything.
      - -ValidateOnly checks every file offline, with no Graph connection.
      - Enforcing (-State Enabled) requires -Force.

.PARAMETER BreakGlassGroupId
    Object ID of a security group that contains your emergency access accounts. It is excluded from every policy.

.PARAMETER PolicyIds
    Import only these policies, for example CA001,CA003. Default: all.

.PARAMETER State
    ReportOnly (default), Disabled, or Enabled. Enabled requires -Force.

.PARAMETER TenantId
    Tenant to connect to. Optional.

.PARAMETER ValidateOnly
    Validate the policy files and exit. No connection is made.

.PARAMETER UseExistingConnection
    Reuse an existing Connect-MgGraph session.

.PARAMETER Force
    Required together with -State Enabled.

.EXAMPLE
    .\Import-CAPolicies.ps1 -ValidateOnly

.EXAMPLE
    .\Import-CAPolicies.ps1 -BreakGlassGroupId 1b2c3d4e-0000-0000-0000-000000000000 -WhatIf

.EXAMPLE
    .\Import-CAPolicies.ps1 -BreakGlassGroupId 1b2c3d4e-0000-0000-0000-000000000000 -PolicyIds CA001,CA002,CA003

.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
    Scopes : Policy.ReadWrite.ConditionalAccess, Policy.Read.All, Group.Read.All
    Role   : Conditional Access Administrator or Security Administrator
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BreakGlassGroupId,
    [string[]]$PolicyIds,
    [ValidateSet('ReportOnly', 'Disabled', 'Enabled')][string]$State = 'ReportOnly',
    [string]$TenantId,
    [string]$PolicyPath = (Join-Path $PSScriptRoot 'policies'),
    [switch]$ValidateOnly,
    [switch]$UseExistingConnection,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$stateMap = @{ ReportOnly = 'enabledForReportingButNotEnforced'; Disabled = 'disabled'; Enabled = 'enabled' }
$placeholder = '{{BREAK_GLASS_GROUP_ID}}'
$guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

function Write-Line { param([string]$Text, [string]$Color = 'Gray') Write-Host "  $Text" -ForegroundColor $Color }

# ---------------------------------------------------------------------------------------------
#  Load and validate policy files (offline)
# ---------------------------------------------------------------------------------------------
function Get-PolicyFiles {
    $files = Get-ChildItem -Path $PolicyPath -Filter 'CA*.json' | Sort-Object Name
    if ($PolicyIds) {
        $wanted = @($PolicyIds | ForEach-Object { $_ -split '[,; ]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToUpper() })
        $files = $files | Where-Object { $wanted -contains $_.Name.Split('-')[0].ToUpper() }
    }
    if (-not $files) { throw "No policy files found in $PolicyPath matching the selection." }
    $files
}

function Test-PolicyObject {
    param($Policy, [string]$File)
    $errors = @()
    foreach ($req in 'displayName', 'state', 'conditions') {
        if (-not $Policy.PSObject.Properties[$req]) { $errors += "missing '$req'" }
    }
    $c = $Policy.conditions
    if ($c) {
        if (-not $c.users) { $errors += "missing 'conditions.users'" }
        if (-not $c.applications) { $errors += "missing 'conditions.applications'" }
        $u = $c.users
        if ($u -and -not (@($u.includeUsers).Count + @($u.includeGroups).Count + @($u.includeRoles).Count)) { $errors += 'no users, groups or roles included' }
        if ($u -and @($u.excludeGroups) -notcontains $placeholder) { $errors += "break-glass placeholder not in excludeGroups" }
    }
    if (-not $Policy.grantControls -and -not $Policy.sessionControls) { $errors += 'needs grantControls or sessionControls' }
    if ($Policy.grantControls) {
        $g = $Policy.grantControls
        if (-not (@($g.builtInControls).Count) -and -not $g.authenticationStrength) { $errors += 'grantControls has no controls' }
        if ($g.operator -notin 'AND', 'OR') { $errors += "grantControls.operator must be AND or OR" }
    }
    if ($Policy.displayName -notmatch '^CA\d{3} - ') { $errors += "displayName should start with 'CAnnn - '" }
    $errors
}

Write-Host ''
Write-Line 'Conditional Access Policy Library - import' 'White'
Write-Host ''

$files = @(Get-PolicyFiles)
$policies = @()
$bad = 0
foreach ($f in $files) {
    try { $obj = Get-Content $f.FullName -Raw | ConvertFrom-Json }
    catch { Write-Line "[INVALID] $($f.Name): not valid JSON - $($_.Exception.Message)" 'Red'; $bad++; continue }
    $errs = @(Test-PolicyObject $obj $f.Name)
    if ($errs.Count) { Write-Line "[INVALID] $($f.Name): $($errs -join '; ')" 'Red'; $bad++; continue }
    $policies += [pscustomobject]@{ File = $f; Name = $obj.displayName; Raw = (Get-Content $f.FullName -Raw) }
    if ($ValidateOnly) { Write-Line "[OK] $($obj.displayName)" 'Green' }
}
if ($bad) { throw "$bad policy file(s) failed validation. Nothing was imported." }
if ($ValidateOnly) { Write-Host ''; Write-Line "All $($policies.Count) policy files are valid." 'Green'; Write-Host ''; return }

# ---------------------------------------------------------------------------------------------
#  Guard rails
# ---------------------------------------------------------------------------------------------
if (-not $BreakGlassGroupId) { throw '-BreakGlassGroupId is required. Create a security group with your emergency access accounts and pass its object ID.' }
if ($BreakGlassGroupId -notmatch $guidPattern) { throw "-BreakGlassGroupId '$BreakGlassGroupId' is not a valid object ID (GUID)." }
if ($State -eq 'Enabled' -and -not $Force) { throw "Importing policies as Enabled can lock users out. Import as ReportOnly, review the sign-in logs, then rerun with -State Enabled -Force if you really want to enforce." }

# ---------------------------------------------------------------------------------------------
#  Connect
# ---------------------------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication is required: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
if (-not $UseExistingConnection) {
    $p = @{ Scopes = 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Group.Read.All'; NoWelcome = $true }
    if ($TenantId) { $p.TenantId = $TenantId }
    Connect-MgGraph @p
} elseif (-not (Get-MgContext)) { throw 'No Microsoft Graph connection. Run Connect-MgGraph first.' }

$group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$BreakGlassGroupId`?`$select=id,displayName,securityEnabled" -OutputType PSObject
if (-not $group.securityEnabled) { throw "Group '$($group.displayName)' is not a security group." }
$members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$BreakGlassGroupId/members?`$select=id" -OutputType PSObject
$memberCount = @($members.value).Count
Write-Line "Break-glass group: $($group.displayName) ($memberCount member(s))" 'Cyan'
if ($memberCount -eq 0) { Write-Line 'Warning: the break-glass group is empty. Add your emergency access accounts before enforcing any policy.' 'Yellow' }

$existing = @{}
$next = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state'
while ($next) {
    $r = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
    foreach ($e in $r.value) { $existing[$e.displayName] = $e }
    $next = $r.'@odata.nextLink'
}

# ---------------------------------------------------------------------------------------------
#  Import
# ---------------------------------------------------------------------------------------------
$created = 0; $skipped = 0; $failed = 0
Write-Line "Target state: $State" 'Cyan'
Write-Host ''
foreach ($p in $policies) {
    if ($existing.ContainsKey($p.Name)) { Write-Line "[SKIP]    $($p.Name) (already exists, state: $($existing[$p.Name].state))" 'DarkGray'; $skipped++; continue }
    $body = $p.Raw.Replace($placeholder, $BreakGlassGroupId) | ConvertFrom-Json
    $body.state = $stateMap[$State]
    $json = $body | ConvertTo-Json -Depth 20
    if ($PSCmdlet.ShouldProcess($p.Name, "Create Conditional Access policy ($State)")) {
        try {
            $null = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body $json -ContentType 'application/json'
            Write-Line "[CREATED] $($p.Name)" 'Green'; $created++
        } catch {
            $msg = $_.ErrorDetails.Message; if (-not $msg) { $msg = $_.Exception.Message }
            Write-Line "[FAILED]  $($p.Name): $msg" 'Red'; $failed++
        }
    }
}

Write-Host ''
Write-Line "Created: $created   Skipped: $skipped   Failed: $failed" 'White'
if ($State -eq 'ReportOnly' -and $created) {
    Write-Line 'Next: watch Entra admin center > Sign-in logs > Report-only tab for 1-2 weeks, then turn policies On one at a time.' 'Cyan'
}
Write-Host ''
