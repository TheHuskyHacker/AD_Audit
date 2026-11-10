# AD Security Audit Toolkit

Single-script Active Directory security auditor. One file, one run: finds stale accounts, privilege-escalation paths, group hygiene issues, password-policy weaknesses, and maps the full attack surface. Exports all findings to timestamped CSVs with severity ratings.

## Quick Start

```powershell
# Drop on any domain-joined machine and run
.\AD-Full-Audit.ps1

# Custom stale threshold (default 90 days)
.\AD-Full-Audit.ps1 -InactiveDays 60

# Include Print Spooler / SMBv1 checks on DCs (requires network access)
.\AD-Full-Audit.ps1 -CheckRemoteServices

# Custom output directory
.\AD-Full-Audit.ps1 -OutputDir "C:\Audits\Q4-2026"

# Full custom run
.\AD-Full-Audit.ps1 -InactiveDays 60 -PasswordAgeDays 120 -NestingDepthThreshold 2 -OutputDir "C:\Audits" -CheckRemoteServices
```

## What It Checks

### Stale Accounts
- Users/computers inactive for N days (configurable, default 90)
- Accounts that have **never logged in**
- Expired accounts still enabled
- Passwords older than N days (configurable, default 180)
- `PasswordNeverExpires` flag set
- Disabled accounts still sitting in privileged groups
- Machines running unsupported OS (XP, Vista, 7, Server 2008/2012)

### Privileged Access
- Full recursive enumeration of all privileged group memberships
- Nested group chains that grant unintended privilege
- Kerberoastable accounts in admin groups (SPN + DA = game over)
- **AdminCount=1 orphans** — removed from priv groups but ACL inheritance still broken by AdminSDHolder
- Unconstrained delegation on non-DC hosts (TGT harvesting)
- Constrained delegation to sensitive services (LDAP on DCs, krbtgt)
- Protocol transition misconfigs

### Group Hygiene
- Empty security groups (often still referenced in ACLs)
- Groups where all members reside outside the group's OU
- Orphaned/unresolvable SIDs in group memberships (deleted accounts)
- Deeply nested group chains (configurable depth threshold)
- Security groups with no ManagedBy owner

### Password & Authentication Policy
- Domain-wide password policy weaknesses (min length, lockout, complexity, reversible encryption)
- Fine-Grained Password Policies (FGPPs) with weak settings
- Per-account dangerous flags:
  - `DoesNotRequirePreAuth` (AS-REP roastable)
  - `AllowReversiblePasswordEncryption`
  - `PasswordNotRequired`
  - `CannotChangePassword`
  - `PasswordNeverExpires`
- Privileged accounts with any of the above flagged as CRITICAL

### Attack Surface Mapping
- **Kerberoastable accounts** — SPNs on user accounts with password age tracking (older = easier to crack)
- **AS-REP roastable accounts** — no Kerberos pre-authentication
- **LAPS deployment gaps** — per-machine coverage with percentage tracking
- **SIDHistory persistence** — migration residue that attackers use for privilege persistence
- **Domain trust relationships** — SID filtering status (disabled = CRITICAL)
- **DES-only Kerberos** accounts (weak encryption)
- **Print Spooler on DCs** — PrintNightmare / coerce attack vector (with `-CheckRemoteServices`)
- **SMBv1 on DCs** — EternalBlue and relay attacks (with `-CheckRemoteServices`)

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-InactiveDays` | 90 | Days since last logon to flag as stale |
| `-PasswordAgeDays` | 180 | Days since password last set to flag |
| `-NestingDepthThreshold` | 3 | Group nesting depth to flag as excessive |
| `-OutputDir` | `.\AuditReports` | Directory for CSV output (auto-created) |
| `-CheckRemoteServices` | Off | Probe DCs for Print Spooler and SMBv1 |

## Output

All reports land in `.\AuditReports\` (or your custom path), timestamped:

```
AuditReports/
  StaleUsers_2026-11-10_143000.csv
  StaleComputers_2026-11-10_143000.csv
  DisabledPrivileged_2026-11-10_143000.csv
  PrivilegedAccess_2026-11-10_143000.csv
  AdminCountOrphans_2026-11-10_143000.csv
  DelegationIssues_2026-11-10_143000.csv
  GroupHygiene_2026-11-10_143000.csv
  PasswordPolicy_2026-11-10_143000.csv
  AccountFlags_2026-11-10_143000.csv
  Kerberoastable_2026-11-10_143000.csv
  ASREPRoastable_2026-11-10_143000.csv
  LAPS_Gaps_2026-11-10_143000.csv
  SIDHistory_2026-11-10_143000.csv
  DomainTrusts_2026-11-10_143000.csv
  WeakKerberos_2026-11-10_143000.csv
  RemoteServices_2026-11-10_143000.csv      # only with -CheckRemoteServices
  ExecutiveSummary_2026-11-10_143000.csv     # master rollup
```

Every finding CSV includes a `Severity` column (CRITICAL / HIGH / MEDIUM / LOW) for sorting and triage. Most also include a `Remediation` column with the fix.

The `ExecutiveSummary` CSV gives a single-page rollup across all categories with severity counts — hand this to leadership or use it as the cover page for a formal report.

## Requirements

- **PowerShell 5.1+** (or 7+)
- **ActiveDirectory module** — `Import-Module ActiveDirectory` (comes with RSAT)
- **Domain read access** — Domain Admin is NOT required for the base audit
- **LAPS read access** — read permission on `ms-Mcs-AdmPwd` attribute for LAPS coverage checks
- **WinRM access to DCs** — only needed if using `-CheckRemoteServices`

## Performance Notes

The script pulls `Get-ADUser` and `Get-ADComputer` with all needed properties in a single query each at startup, then reuses those collections across every check. This avoids redundant LDAP queries and makes it significantly faster than running separate scripts that each query AD independently. On large domains (10k+ objects), expect 2-5 minutes for the full audit.
