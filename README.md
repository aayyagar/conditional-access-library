# Conditional Access Policy Library

Twelve ready-to-deploy Microsoft Entra ID Conditional Access policies, a safe import script that loads them in **report-only mode**, and a guide that explains each one.

Built from real enterprise rollouts: the policies follow the order most organizations deploy them, and every policy excludes a break-glass group so you cannot lock yourself out.

## The policies

| ID | Policy | Category | Severity | License |
|---|---|---|---|---|
| CA001 | [Block legacy authentication](policies/CA001-block-legacy-authentication.json) | Foundation | Critical | Entra ID P1 |
| CA002 | [Require phishing-resistant MFA for administrators](policies/CA002-require-phishing-resistant-mfa-for-administrators.json) | Privileged access | Critical | Entra ID P1 |
| CA003 | [Require MFA for all users](policies/CA003-require-mfa-for-all-users.json) | Foundation | Critical | Entra ID P1 |
| CA004 | [Require MFA for Azure management](policies/CA004-require-mfa-for-azure-management.json) | Privileged access | High | Entra ID P1 |
| CA005 | [Require MFA for guests and external users](policies/CA005-require-mfa-for-guests-and-external-users.json) | Foundation | High | Entra ID P1 |
| CA006 | [Require compliant or hybrid-joined device (Windows and macOS)](policies/CA006-require-compliant-or-hybrid-joined-device-windows-and-macos.json) | Devices | High | Entra ID P1 + Intune |
| CA007 | [Block unknown or unsupported device platforms](policies/CA007-block-unknown-or-unsupported-device-platforms.json) | Devices | Medium | Entra ID P1 |
| CA008 | [Require MFA for medium and high sign-in risk](policies/CA008-require-mfa-for-medium-and-high-sign-in-risk.json) | Risk | High | Entra ID P2 |
| CA009 | [Require secure password change for high user risk](policies/CA009-require-secure-password-change-for-high-user-risk.json) | Risk | High | Entra ID P2 |
| CA010 | [Secure security info registration](policies/CA010-secure-security-info-registration.json) | Foundation | Medium | Entra ID P1 |
| CA011 | [Admin session limits](policies/CA011-admin-session-limits.json) | Privileged access | Medium | Entra ID P1 |
| CA012 | [Require app protection on mobile devices](policies/CA012-require-app-protection-on-mobile-devices.json) | Devices | Medium | Entra ID P1 + Intune |

Read the [policy guide](GUIDE.md) for what each policy does, why it matters, and what to check before enforcing it.

## Quick start

```powershell
# 1. Check the policy files offline (no connection needed)
.\Import-CAPolicies.ps1 -ValidateOnly

# 2. Back up your existing policies
.\Export-CAPolicies.ps1

# 3. Preview what would be created
.\Import-CAPolicies.ps1 -BreakGlassGroupId <group-object-id> -WhatIf

# 4. Import all policies in report-only mode
.\Import-CAPolicies.ps1 -BreakGlassGroupId <group-object-id>

# Or import only some of them
.\Import-CAPolicies.ps1 -BreakGlassGroupId <group-object-id> -PolicyIds CA001,CA002,CA003
```

## Safety by design

- **Report-only by default.** Policies log what they would do without blocking anyone.
- **Break-glass exclusion is mandatory.** The script refuses to run without a break-glass group ID, checks that the group exists and is a security group, and warns if it is empty.
- **Idempotent.** Policies that already exist with the same name are skipped, so it is safe to run again.
- **Enforcing needs a deliberate choice.** `-State Enabled` only works together with `-Force`.
- **Offline validation.** `-ValidateOnly` checks every file for required fields, controls and the break-glass placeholder.

## Import script parameters

| Parameter | Description |
|---|---|
| `-BreakGlassGroupId` | Object ID of the security group holding your emergency access accounts (required) |
| `-PolicyIds` | Import only selected policies, for example `CA001,CA003` |
| `-State` | `ReportOnly` (default), `Disabled`, or `Enabled` (requires `-Force`) |
| `-TenantId` | Tenant to connect to |
| `-ValidateOnly` | Validate files offline and exit |
| `-WhatIf` | Show what would be created without creating anything |
| `-UseExistingConnection` | Reuse an existing `Connect-MgGraph` session |

## Requirements

- PowerShell 5.1 or 7+
- `Microsoft.Graph.Authentication` module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- Conditional Access Administrator or Security Administrator role
- Microsoft Entra ID P1 (P2 for CA008 and CA009, Intune for CA006 and CA012)

## Repository layout

```
policies/              One Microsoft Graph JSON file per policy
catalog.json           Policy metadata: category, severity, license, rationale
Import-CAPolicies.ps1  Validates and imports policies (report-only by default)
Export-CAPolicies.ps1  Backs up existing tenant policies to JSON
GUIDE.md               What each policy does and how to roll it out
```

## Related

- [Entra ID Security Posture Checker](https://github.com/aayyagar/entra-posture-checker): scores your tenant, including whether these policies are in place.

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## Disclaimer

Test in a non-production tenant or in report-only mode first. Review every policy against your own environment before enforcing it.

## License

MIT
