# Conditional Access Policy Guide

This guide explains every policy in the library: what it does, why it matters, what it will affect, and how to roll it out safely.

## Before you start

1. **Create two break-glass accounts.** Cloud-only accounts on the `onmicrosoft.com` domain with long random passwords (or FIDO2 keys), stored securely, with the Global Administrator role. Put them in a security group. Every policy excludes that group, so you can never lock yourself out.
2. **Monitor the break-glass accounts.** Send an alert whenever they sign in.
3. **Back up your current policies** with `Export-CAPolicies.ps1`.
4. **Import everything in report-only mode.** Report-only policies are evaluated on every sign-in and logged, but nothing is blocked.
5. **Review for 1–2 weeks.** In the Entra admin center, open Sign-in logs and use the *Report-only* tab, or the Conditional Access *Insights and reporting* workbook, to see who each policy would affect.
6. **Turn policies on one at a time**, starting with the Foundation group, and communicate each change to users.

## Recommended rollout order

| Phase | Policies | Notes |
|---|---|---|
| 1. Foundation | CA001, CA003, CA005, CA010 | Biggest risk reduction; works with Entra ID P1 |
| 2. Privileged access | CA002, CA004, CA011 | Issue FIDO2 keys or passkeys to admins first |
| 3. Risk | CA008, CA009 | Requires Entra ID P2 |
| 4. Devices | CA006, CA007, CA012 | Requires Intune enrollment and app protection policies |

## Policies

### CA001 - Block legacy authentication

**Category:** Foundation · **Severity:** Critical · **License:** Entra ID P1 · **File:** [`policies/CA001-block-legacy-authentication.json`](policies/CA001-block-legacy-authentication.json)

Blocks Exchange ActiveSync and other legacy protocols (POP, IMAP, SMTP AUTH, older Office clients) for everyone.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Client apps | Exchange ActiveSync, Other clients |
| Controls | Block access |

**Why it matters.** Legacy protocols cannot perform MFA, so attackers use them for password spray and credential stuffing. Microsoft reports that the vast majority of password spray attacks use legacy authentication.

**What to check before enforcing.** Old mail clients, multifunction printers and scripts that use basic authentication will stop working. Check sign-in logs filtered by Client app before enforcing.

### CA002 - Require phishing-resistant MFA for administrators

**Category:** Privileged access · **Severity:** Critical · **License:** Entra ID P1 · **File:** [`policies/CA002-require-phishing-resistant-mfa-for-administrators.json`](policies/CA002-require-phishing-resistant-mfa-for-administrators.json)

Requires the built-in Phishing-resistant MFA authentication strength (FIDO2 security key, passkey, Windows Hello for Business or certificate) for 15 admin roles.

| Setting | Value |
|---|---|
| Users | 15 admin roles |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Controls | Authentication strength: Phishing-resistant MFA |

**Why it matters.** Admin accounts are the top target. Push notifications and one-time codes can be phished through adversary-in-the-middle proxies; phishing-resistant methods are bound to the real sign-in site.

**What to check before enforcing.** Admins without a FIDO2 key, passkey or Windows Hello for Business will be blocked. Issue methods first, and use a Temporary Access Pass to bootstrap registration.

### CA003 - Require MFA for all users

**Category:** Foundation · **Severity:** Critical · **License:** Entra ID P1 · **File:** [`policies/CA003-require-mfa-for-all-users.json`](policies/CA003-require-mfa-for-all-users.json)

Requires multifactor authentication for every user and every cloud app.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group, Directory Synchronization Accounts role |
| Target | All cloud apps |
| Controls | Require MFA |

**Why it matters.** MFA blocks the large majority of account compromise attacks that rely on stolen or guessed passwords.

**What to check before enforcing.** Users must register an MFA method. The Directory Synchronization Accounts role is excluded so Entra Connect keeps syncing; exclude other service accounts only if they cannot use workload identities.

### CA004 - Require MFA for Azure management

**Category:** Privileged access · **Severity:** High · **License:** Entra ID P1 · **File:** [`policies/CA004-require-mfa-for-azure-management.json`](policies/CA004-require-mfa-for-azure-management.json)

Requires MFA for the Azure portal, Azure CLI, Azure PowerShell and other tools that use Azure Resource Manager.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | Azure management (Azure Resource Manager) |
| Controls | Require MFA |

**Why it matters.** Anyone with an Azure RBAC role can change infrastructure. This closes the gap for users who hold subscription roles but no Entra admin role.

**What to check before enforcing.** Automation that signs in as a user to Azure Resource Manager will need to move to a managed identity or service principal.

### CA005 - Require MFA for guests and external users

**Category:** Foundation · **Severity:** High · **License:** Entra ID P1 · **File:** [`policies/CA005-require-mfa-for-guests-and-external-users.json`](policies/CA005-require-mfa-for-guests-and-external-users.json)

Requires MFA for B2B guests and other external users.

| Setting | Value |
|---|---|
| Users | Guests and external users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Controls | Require MFA |

**Why it matters.** Guest accounts are protected by another organization's security. Requiring MFA in your tenant ensures a stolen guest password alone cannot reach your data.

**What to check before enforcing.** Guests register MFA in your tenant on first access, unless you trust their home tenant's MFA through cross-tenant access settings.

### CA006 - Require compliant or hybrid-joined device (Windows and macOS)

**Category:** Devices · **Severity:** High · **License:** Entra ID P1 + Intune · **File:** [`policies/CA006-require-compliant-or-hybrid-joined-device-windows-and-macos.json`](policies/CA006-require-compliant-or-hybrid-joined-device-windows-and-macos.json)

Allows desktop access only from devices that are Intune compliant or Microsoft Entra hybrid joined.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Platforms | windows, macOS |
| Controls | Require compliant device OR Require hybrid-joined device |

**Why it matters.** Stolen credentials and session tokens are far less useful when access also requires a managed, healthy device.

**What to check before enforcing.** Personal computers lose access. Roll out device enrollment and compliance policies first, and keep this in report-only until the logs show near-full compliance.

### CA007 - Block unknown or unsupported device platforms

**Category:** Devices · **Severity:** Medium · **License:** Entra ID P1 · **File:** [`policies/CA007-block-unknown-or-unsupported-device-platforms.json`](policies/CA007-block-unknown-or-unsupported-device-platforms.json)

Blocks sign-ins from device platforms that are not Android, iOS, Windows, macOS or Linux.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Platforms | all (excluding android, iOS, windows, macOS, linux) |
| Controls | Block access |

**Why it matters.** Attack tooling often sends unusual or spoofed platform strings. Blocking unknown platforms removes a common way around device-based policies.

**What to check before enforcing.** Rarely affects real users. Check report-only results for legitimate unusual clients before enforcing.

### CA008 - Require MFA for medium and high sign-in risk

**Category:** Risk · **Severity:** High · **License:** Entra ID P2 · **File:** [`policies/CA008-require-mfa-for-medium-and-high-sign-in-risk.json`](policies/CA008-require-mfa-for-medium-and-high-sign-in-risk.json)

When Microsoft Entra ID Protection rates a sign-in as medium or high risk, the user must complete MFA every time.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Sign-in risk | high, medium |
| Controls | Require MFA; Sign-in frequency: every time |

**Why it matters.** Catches sign-ins from anonymous IPs, impossible travel, password spray patterns and token anomalies, and challenges them in real time.

**What to check before enforcing.** Needs Entra ID P2. Users must already be registered for MFA, or risky sign-ins will be blocked.

### CA009 - Require secure password change for high user risk

**Category:** Risk · **Severity:** High · **License:** Entra ID P2 · **File:** [`policies/CA009-require-secure-password-change-for-high-user-risk.json`](policies/CA009-require-secure-password-change-for-high-user-risk.json)

When a user's credentials are likely compromised (for example, found in a leak), they must complete MFA and change their password.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| User risk | high |
| Controls | Require MFA AND Require password change; Sign-in frequency: every time |

**Why it matters.** Lets users remediate their own leaked credentials immediately instead of waiting for the help desk.

**What to check before enforcing.** Needs Entra ID P2 and self-service password reset. For hybrid users, enable password writeback.

### CA010 - Secure security info registration

**Category:** Foundation · **Severity:** Medium · **License:** Entra ID P1 · **File:** [`policies/CA010-secure-security-info-registration.json`](policies/CA010-secure-security-info-registration.json)

Requires MFA to register or change MFA methods from outside your trusted locations.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group, Guests and external users |
| Target | Register security information (user action) |
| Locations | any, except trusted locations |
| Controls | Require MFA |

**Why it matters.** If an attacker gets a password before the user registers MFA, they could register their own phone. This stops that.

**What to check before enforcing.** New hires working remotely need a Temporary Access Pass to register their first method. Define trusted named locations before enforcing.

### CA011 - Admin session limits

**Category:** Privileged access · **Severity:** Medium · **License:** Entra ID P1 · **File:** [`policies/CA011-admin-session-limits.json`](policies/CA011-admin-session-limits.json)

Admins re-authenticate every 4 hours and browser sessions are never persistent.

| Setting | Value |
|---|---|
| Users | 15 admin roles |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Controls | Sign-in frequency: 4 hours; Persistent browser: never |

**Why it matters.** Limits how long a stolen admin session cookie stays useful and stops 'stay signed in' on shared machines.

**What to check before enforcing.** Admins sign in more often. Pair with PIM so admin roles are only active when needed.

### CA012 - Require app protection on mobile devices

**Category:** Devices · **Severity:** Medium · **License:** Entra ID P1 + Intune · **File:** [`policies/CA012-require-app-protection-on-mobile-devices.json`](policies/CA012-require-app-protection-on-mobile-devices.json)

On iOS and Android, allows access only through apps with an Intune app protection policy, such as Outlook and Teams.

| Setting | Value |
|---|---|
| Users | All users |
| Excluded | Break-glass group |
| Target | All cloud apps |
| Platforms | android, iOS |
| Controls | Require app protection policy |

**Why it matters.** Protects company data on personal phones (blocks copy/paste to personal apps, enables selective wipe) without enrolling the whole device.

**What to check before enforcing.** Native mail apps and unsupported third-party apps lose access. Create Intune app protection policies first.

## Admin roles covered by CA002 and CA011

| Role | Template ID |
|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| Privileged Authentication Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| Conditional Access Administrator | `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9` |
| Exchange Administrator | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| SharePoint Administrator | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| Authentication Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |
| Helpdesk Administrator | `729827e3-9c14-49f7-bb1b-9608f156bbb8` |
| Billing Administrator | `b0f54661-2d74-4c50-afa3-1ec803f12efe` |
| Hybrid Identity Administrator | `8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2` |
| Intune Administrator | `3a2c62db-5318-420d-8d74-23affee5d9d5` |

## Troubleshooting

- **"The policy contains invalid data"**: usually a license gap (risk conditions need P2) or an object ID that does not exist in your tenant. Check the break-glass group ID.
- **A user is blocked unexpectedly**: open the sign-in log entry, go to the *Conditional Access* tab, and see which policy applied and why. The *What If* tool in the Conditional Access blade lets you test a user before enforcing.
- **Service accounts failing MFA**: move them to workload identities (service principals or managed identities). If that is not possible, exclude them by group and protect them with a location-based policy.
