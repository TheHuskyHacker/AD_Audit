#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Complete Active Directory security audit — single script, all findings to CSV.
.DESCRIPTION
    Runs all audit checks in one pass:
    - Stale/dead user and computer accounts
    - Privileged access enumeration (recursive nesting, AdminCount orphans)
    - Delegation misconfigs (unconstrained, constrained, protocol transition)
    - Group hygiene (empty groups, orphaned SIDs, OU mismatches, deep nesting)
    - Password policy weaknesses (domain, FGPP, per-account flags)
    - Attack surface mapping (Kerberoastable, AS-REP, LAPS gaps, SIDHistory, trusts, weak Kerberos)
    - Optional: remote service checks (Print Spooler, SMBv1 on DCs)

    Outputs individual CSVs per category + a master ExecutiveSummary CSV.
.PARAMETER InactiveDays
    Days since last logon to flag as stale. Default 90.
.PARAMETER PasswordAgeDays
    Days since password last set to flag. Default 180.
.PARAMETER NestingDepthThreshold
    Group nesting depth to flag. Default 3.
.PARAMETER OutputDir
    Directory for CSV output. Default .\AuditReports
.PARAMETER CheckRemoteServices
    If set, probes DCs for Print Spooler and SMBv1 (requires network access to DCs).
.EXAMPLE
    .\AD-Full-Audit.ps1
.EXAMPLE
    .\AD-Full-Audit.ps1 -InactiveDays 60 -CheckRemoteServices
.EXAMPLE
    .\AD-Full-Audit.ps1 -OutputDir "C:\Audits\Q4"
#>
[CmdletBinding()]
param(
    [int]$InactiveDays = 90,
    [int]$PasswordAgeDays = 180,
    [int]$NestingDepthThreshold = 3,
    [string]$OutputDir = ".\AuditReports",
    [switch]$CheckRemoteServices
)

$ErrorActionPreference = "Continue"
Import-Module ActiveDirectory -ErrorAction Stop

# ============================================================
# SETUP
# ============================================================
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$cutoffDate = (Get-Date).AddDays(-$InactiveDays)
$pwdCutoff  = (Get-Date).AddDays(-$PasswordAgeDays)

$domainInfo = Get-ADDomain
$forestInfo = Get-ADForest
$domainDN   = $domainInfo.DistinguishedName

Write-Host @"

    +==================================================+
    |       AD Security Audit Toolkit v1.0              |
    |       Single-Script Full Domain Audit             |
    +==================================================+

"@ -ForegroundColor Cyan

Write-Host "[*] Domain:       $($domainInfo.DNSRoot)" -ForegroundColor White
Write-Host "[*] Forest:       $($forestInfo.Name)" -ForegroundColor White
Write-Host "[*] Forest Level: $($forestInfo.ForestMode)" -ForegroundColor White
Write-Host "[*] Domain Level: $($domainInfo.DomainMode)" -ForegroundColor White
Write-Host "[*] DCs:          $(($domainInfo.ReplicaDirectoryServers | Measure-Object).Count)" -ForegroundColor White
Write-Host "[*] Inactive threshold: $InactiveDays days" -ForegroundColor White
Write-Host "[*] Password age threshold: $PasswordAgeDays days" -ForegroundColor White
Write-Host "[*] Output:       $OutputDir" -ForegroundColor White
Write-Host ""

$totalStart = Get-Date

# Privileged group names used across multiple checks
$privGroupNames = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "DnsAdmins",
    "Group Policy Creator Owners", "Cert Publishers"
)

# Builtin group SIDs to skip in group hygiene
$builtinGroupSIDs = @(
    "S-1-5-32-544","S-1-5-32-545","S-1-5-32-546","S-1-5-32-547",
    "S-1-5-32-548","S-1-5-32-549","S-1-5-32-550","S-1-5-32-551",
    "S-1-5-32-552","S-1-5-32-554","S-1-5-32-555","S-1-5-32-556",
    "S-1-5-32-557","S-1-5-32-558","S-1-5-32-559","S-1-5-32-560",
    "S-1-5-32-561","S-1-5-32-562","S-1-5-32-568","S-1-5-32-569",
    "S-1-5-32-573","S-1-5-32-574","S-1-5-32-575","S-1-5-32-576",
    "S-1-5-32-577","S-1-5-32-578","S-1-5-32-579","S-1-5-32-580",
    "S-1-5-32-581","S-1-5-32-582"
)

# Severity counters
$script:totalCritical = 0
$script:totalHigh     = 0
$script:totalMedium   = 0
$script:totalLow      = 0

function Export-Finding {
    param(
        [string]$Name,
        [array]$Data
    )
    if ($Data.Count -eq 0) { return }
    $path = Join-Path $OutputDir "${Name}_${timestamp}.csv"
    $Data | Export-Csv -Path $path -NoTypeInformation
    # Tally severities
    $script:totalCritical += ($Data | Where-Object Severity -eq "CRITICAL" | Measure-Object).Count
    $script:totalHigh     += ($Data | Where-Object Severity -eq "HIGH"     | Measure-Object).Count
    $script:totalMedium   += ($Data | Where-Object Severity -eq "MEDIUM"   | Measure-Object).Count
    $script:totalLow      += ($Data | Where-Object Severity -eq "LOW"      | Measure-Object).Count
    Write-Host "    -> $path ($($Data.Count) rows)" -ForegroundColor Green
}

# ============================================================
# 1. STALE ACCOUNTS
# ============================================================
Write-Host "`n[========== STALE ACCOUNTS ==========]" -ForegroundColor Cyan

# --- Stale Users ---
Write-Host "[+] Scanning user accounts..." -ForegroundColor Yellow

$allUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties `
    LastLogonTimestamp, PasswordLastSet, AccountExpirationDate, `
    WhenCreated, MemberOf, DistinguishedName, Description, `
    PasswordNeverExpires, ServicePrincipalName, AdminCount, `
    AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, `
    PasswordNotRequired, CannotChangePassword, UserAccountControl, `
    UseDESKeyOnly, SIDHistory, TrustedForDelegation

$staleUsers = @()

foreach ($user in $allUsers) {
    $lastLogon = if ($user.LastLogonTimestamp) {
        [DateTime]::FromFileTime($user.LastLogonTimestamp)
    } else { $null }

    $issues = @()

    if (-not $user.LastLogonTimestamp) {
        $issues += "NEVER_LOGGED_IN"
    } elseif ($lastLogon -lt $cutoffDate) {
        $issues += "INACTIVE_${InactiveDays}d"
    }

    if ($user.PasswordLastSet -and $user.PasswordLastSet -lt $pwdCutoff) {
        $issues += "PASSWORD_OLD_$([math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays))d"
    }

    if ($user.PasswordNeverExpires) {
        $issues += "PWD_NEVER_EXPIRES"
    }

    if ($user.AccountExpirationDate -and $user.AccountExpirationDate -lt (Get-Date)) {
        $issues += "EXPIRED_STILL_ENABLED"
    }

    if ($issues.Count -gt 0) {
        $staleUsers += [PSCustomObject]@{
            SamAccountName  = $user.SamAccountName
            DisplayName     = $user.Name
            Issues          = ($issues -join "; ")
            LastLogon       = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "NEVER" }
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd") } else { "N/A" }
            AccountExpires  = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString("yyyy-MM-dd") } else { "N/A" }
            Created         = $user.WhenCreated.ToString("yyyy-MM-dd")
            OU              = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
            Description     = $user.Description
            GroupCount      = ($user.MemberOf | Measure-Object).Count
            Severity        = if ($issues -match "NEVER_LOGGED_IN|EXPIRED_STILL_ENABLED") { "HIGH" }
                              elseif ($issues -match "PWD_NEVER_EXPIRES") { "MEDIUM" }
                              else { "LOW" }
        }
    }
}

Write-Host "    Stale users: $($staleUsers.Count)" -ForegroundColor White
Export-Finding -Name "StaleUsers" -Data $staleUsers

# --- Stale Computers ---
Write-Host "[+] Scanning computer accounts..." -ForegroundColor Yellow

$allComputers = Get-ADComputer -Filter {Enabled -eq $true} -Properties `
    LastLogonTimestamp, PasswordLastSet, OperatingSystem, `
    OperatingSystemVersion, WhenCreated, DistinguishedName, `
    Description, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, `
    TrustedForDelegation, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation, `
    SIDHistory

$staleComputers = @()

foreach ($comp in $allComputers) {
    $lastLogon = if ($comp.LastLogonTimestamp) {
        [DateTime]::FromFileTime($comp.LastLogonTimestamp)
    } else { $null }

    $issues = @()

    if (-not $comp.LastLogonTimestamp) {
        $issues += "NEVER_LOGGED_IN"
    } elseif ($lastLogon -lt $cutoffDate) {
        $issues += "INACTIVE_${InactiveDays}d"
    }

    if ($comp.PasswordLastSet -and $comp.PasswordLastSet -lt $pwdCutoff) {
        $issues += "MACHINE_PWD_STALE"
    }

    if ($comp.OperatingSystem -match "Windows (XP|Vista|7|8|Server 200[0-8]|Server 2012)") {
        $issues += "UNSUPPORTED_OS"
    }

    if ($issues.Count -gt 0) {
        $staleComputers += [PSCustomObject]@{
            ComputerName    = $comp.Name
            Issues          = ($issues -join "; ")
            OperatingSystem = $comp.OperatingSystem
            OSVersion       = $comp.OperatingSystemVersion
            LastLogon       = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "NEVER" }
            PasswordLastSet = if ($comp.PasswordLastSet) { $comp.PasswordLastSet.ToString("yyyy-MM-dd") } else { "N/A" }
            Created         = $comp.WhenCreated.ToString("yyyy-MM-dd")
            OU              = ($comp.DistinguishedName -replace '^CN=[^,]+,', '')
            Description     = $comp.Description
            Severity        = if ($issues -match "UNSUPPORTED_OS") { "CRITICAL" }
                              elseif ($issues -match "NEVER_LOGGED_IN") { "HIGH" }
                              else { "MEDIUM" }
        }
    }
}

Write-Host "    Stale computers: $($staleComputers.Count)" -ForegroundColor White
Export-Finding -Name "StaleComputers" -Data $staleComputers

# --- Disabled in Priv Groups ---
Write-Host "[+] Checking disabled accounts in privileged groups..." -ForegroundColor Yellow

$disabledPriv = @()
foreach ($group in $privGroupNames) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.objectClass -eq "user") {
                $acct = Get-ADUser -Identity $member.SID -Properties Enabled
                if (-not $acct.Enabled) {
                    $disabledPriv += [PSCustomObject]@{
                        SamAccountName = $acct.SamAccountName
                        Group          = $group
                        Issue          = "DISABLED_IN_PRIV_GROUP"
                        Severity       = "HIGH"
                        Remediation    = "Remove from $group — disabled accounts in priv groups are re-enable targets"
                    }
                }
            }
        }
    } catch { }
}

Write-Host "    Disabled in priv groups: $($disabledPriv.Count)" -ForegroundColor White
Export-Finding -Name "DisabledPrivileged" -Data $disabledPriv


# ============================================================
# 2. PRIVILEGED ACCESS
# ============================================================
Write-Host "`n[========== PRIVILEGED ACCESS ==========]" -ForegroundColor Cyan

# --- Priv Group Membership ---
Write-Host "[+] Enumerating privileged group memberships..." -ForegroundColor Yellow

$privMembers = @()
foreach ($group in $privGroupNames) {
    try {
        $direct = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        foreach ($member in $direct) {
            $isNested = $member.objectClass -eq "group"
            $userObj = $null
            if ($member.objectClass -eq "user") {
                $userObj = Get-ADUser -Identity $member.SID -Properties `
                    LastLogonTimestamp, Enabled, ServicePrincipalName
            }

            $privMembers += [PSCustomObject]@{
                Group          = $group
                MemberName     = $member.Name
                MemberType     = $member.objectClass
                IsNestedGroup  = $isNested
                Enabled        = if ($userObj) { $userObj.Enabled } else { "N/A" }
                LastLogon      = if ($userObj -and $userObj.LastLogonTimestamp) {
                                    ([DateTime]::FromFileTime($userObj.LastLogonTimestamp)).ToString("yyyy-MM-dd")
                                 } else { "N/A" }
                HasSPN         = if ($userObj) { ($userObj.ServicePrincipalName.Count -gt 0) } else { $false }
                Issue          = if ($isNested) { "NESTED_GROUP_PRIV_ESCALATION" }
                                 elseif ($userObj -and $userObj.ServicePrincipalName.Count -gt 0) { "KERBEROASTABLE_ADMIN" }
                                 else { "PRIVILEGED_MEMBER" }
                Severity       = if ($group -match "Domain Admins|Enterprise Admins|Schema Admins") { "CRITICAL" }
                                 elseif ($group -match "DnsAdmins|Backup Operators") { "HIGH" }
                                 else { "MEDIUM" }
            }
        }
    } catch { Write-Warning "Could not enumerate $group : $_" }
}

Write-Host "    Privileged memberships: $($privMembers.Count)" -ForegroundColor White
Export-Finding -Name "PrivilegedAccess" -Data $privMembers

# --- AdminCount Orphans ---
Write-Host "[+] Finding AdminCount=1 orphans..." -ForegroundColor Yellow

$adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1 -and Enabled -eq $true} -Properties AdminCount, MemberOf

$currentPrivSIDs = @()
foreach ($g in $privGroupNames) {
    try {
        $currentPrivSIDs += (Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue).SID.Value
    } catch { }
}
$currentPrivSIDs = $currentPrivSIDs | Sort-Object -Unique

$orphans = @()
foreach ($user in $adminCountUsers) {
    if ($user.SID.Value -notin $currentPrivSIDs) {
        $orphans += [PSCustomObject]@{
            SamAccountName   = $user.SamAccountName
            Issue            = "ADMINCOUNT_ORPHAN"
            Description      = "AdminCount=1 but not in any privileged group — ACL inheritance broken"
            GroupMemberships = ($user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join "; "
            Severity         = "HIGH"
            Remediation      = "Clear AdminCount flag and re-enable inheritance on the account's ACL"
        }
    }
}

Write-Host "    AdminCount orphans: $($orphans.Count)" -ForegroundColor White
Export-Finding -Name "AdminCountOrphans" -Data $orphans


# ============================================================
# 3. DELEGATION
# ============================================================
Write-Host "`n[========== DELEGATION ==========]" -ForegroundColor Cyan

$delegationFindings = @()

# --- Unconstrained Delegation ---
Write-Host "[+] Finding unconstrained delegation..." -ForegroundColor Yellow

$unconstrainedComps = $allComputers | Where-Object {
    $_.TrustedForDelegation -eq $true -and $_.Name -notmatch "^(DC|dc)"
}
foreach ($comp in $unconstrainedComps) {
    $delegationFindings += [PSCustomObject]@{
        Name        = $comp.Name
        Type        = "Computer"
        Issue       = "UNCONSTRAINED_DELEGATION"
        Details     = "Any service ticket stores user's TGT — attacker extracts and reuses"
        OS          = $comp.OperatingSystem
        OU          = ($comp.DistinguishedName -replace '^CN=[^,]+,', '')
        Severity    = "CRITICAL"
        Remediation = "Remove unconstrained delegation; use constrained or RBCD instead"
    }
}

$unconstrainedUsers = $allUsers | Where-Object { $_.TrustedForDelegation -eq $true }
foreach ($user in $unconstrainedUsers) {
    $delegationFindings += [PSCustomObject]@{
        Name        = $user.SamAccountName
        Type        = "User"
        Issue       = "UNCONSTRAINED_DELEGATION_USER"
        Details     = "User account with unconstrained delegation — compromise = full TGT harvest"
        OS          = "N/A"
        OU          = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Severity    = "CRITICAL"
        Remediation = "Remove delegation from user account; use gMSA with constrained delegation"
    }
}

# --- Constrained Delegation ---
Write-Host "[+] Checking constrained delegation..." -ForegroundColor Yellow

$constrainedComps = $allComputers | Where-Object { $_.'msDS-AllowedToDelegateTo' }
foreach ($comp in $constrainedComps) {
    $services = $comp.'msDS-AllowedToDelegateTo' -join "; "
    $proto = if ($comp.TrustedToAuthForDelegation) { "PROTOCOL_TRANSITION" } else { "KERBEROS_ONLY" }

    $sensitive = $false
    foreach ($svc in $comp.'msDS-AllowedToDelegateTo') {
        if ($svc -match "ldap/|cifs/|http/.*dc|krbtgt") { $sensitive = $true }
    }

    $delegationFindings += [PSCustomObject]@{
        Name        = $comp.Name
        Type        = "Computer (Constrained)"
        Issue       = if ($sensitive) { "CONSTRAINED_DELEG_SENSITIVE_SVC" } else { "CONSTRAINED_DELEGATION" }
        Details     = "$proto -> $services"
        OS          = $comp.OperatingSystem
        OU          = ($comp.DistinguishedName -replace '^CN=[^,]+,', '')
        Severity    = if ($sensitive) { "CRITICAL" } elseif ($proto -eq "PROTOCOL_TRANSITION") { "HIGH" } else { "MEDIUM" }
        Remediation = if ($sensitive) { "Review delegation to sensitive service; restrict to specific SPNs" }
                      else { "Verify business need; prefer RBCD where possible" }
    }
}

Write-Host "    Delegation issues: $($delegationFindings.Count)" -ForegroundColor White
Export-Finding -Name "DelegationIssues" -Data $delegationFindings


# ============================================================
# 4. GROUP HYGIENE
# ============================================================
Write-Host "`n[========== GROUP HYGIENE ==========]" -ForegroundColor Cyan

Write-Host "[+] Loading security groups..." -ForegroundColor Yellow

$allGroups = Get-ADGroup -Filter {GroupCategory -eq "Security"} -Properties `
    Members, MemberOf, ManagedBy, WhenCreated, Description, `
    DistinguishedName, GroupScope

$groupFindings = @()

# --- Empty Groups ---
Write-Host "[+] Checking empty security groups..." -ForegroundColor Yellow

foreach ($group in $allGroups) {
    if ($group.SID.Value -in $builtinGroupSIDs) { continue }

    $memberCount = ($group.Members | Measure-Object).Count

    if ($memberCount -eq 0) {
        $groupFindings += [PSCustomObject]@{
            GroupName      = $group.Name
            SamAccountName = $group.SamAccountName
            Issue          = "EMPTY_SECURITY_GROUP"
            Details        = "Zero members — cleanup candidate or orphaned ACL reference"
            MemberCount    = 0
            Scope          = $group.GroupScope
            ManagedBy      = if ($group.ManagedBy) { ($group.ManagedBy -split ',')[0] -replace 'CN=' } else { "NONE" }
            Created        = $group.WhenCreated.ToString("yyyy-MM-dd")
            OU             = ($group.DistinguishedName -replace '^CN=[^,]+,', '')
            Description    = $group.Description
            Severity       = "MEDIUM"
        }
    }
}

# --- All Members Outside OU ---
Write-Host "[+] Checking OU membership alignment..." -ForegroundColor Yellow

foreach ($group in $allGroups) {
    $memberCount = ($group.Members | Measure-Object).Count
    if ($memberCount -eq 0) { continue }

    $groupOU = $group.DistinguishedName -replace '^CN=[^,]+,'
    $membersOutsideOU = 0
    $totalResolvable = 0

    foreach ($memberDN in $group.Members) {
        try {
            $memberOU = $memberDN -replace '^CN=[^,]+,'
            $totalResolvable++
            if ($memberOU -ne $groupOU) { $membersOutsideOU++ }
        } catch { }
    }

    if ($totalResolvable -gt 0 -and $membersOutsideOU -eq $totalResolvable) {
        $groupFindings += [PSCustomObject]@{
            GroupName      = $group.Name
            SamAccountName = $group.SamAccountName
            Issue          = "ALL_MEMBERS_OUTSIDE_OU"
            Details        = "All $totalResolvable members outside this group's OU"
            MemberCount    = $memberCount
            Scope          = $group.GroupScope
            ManagedBy      = if ($group.ManagedBy) { ($group.ManagedBy -split ',')[0] -replace 'CN=' } else { "NONE" }
            Created        = $group.WhenCreated.ToString("yyyy-MM-dd")
            OU             = $groupOU
            Description    = $group.Description
            Severity       = "LOW"
        }
    }
}

# --- Orphaned SIDs ---
Write-Host "[+] Checking orphaned SIDs..." -ForegroundColor Yellow

foreach ($group in $allGroups) {
    foreach ($memberDN in $group.Members) {
        try {
            Get-ADObject -Identity $memberDN -ErrorAction Stop | Out-Null
        } catch {
            $groupFindings += [PSCustomObject]@{
                GroupName      = $group.Name
                SamAccountName = $group.SamAccountName
                Issue          = "ORPHANED_SID"
                Details        = "Unresolvable member: $memberDN"
                MemberCount    = ($group.Members | Measure-Object).Count
                Scope          = $group.GroupScope
                ManagedBy      = if ($group.ManagedBy) { ($group.ManagedBy -split ',')[0] -replace 'CN=' } else { "NONE" }
                Created        = $group.WhenCreated.ToString("yyyy-MM-dd")
                OU             = ($group.DistinguishedName -replace '^CN=[^,]+,', '')
                Description    = $group.Description
                Severity       = "MEDIUM"
            }
        }
    }
}

# --- Deep Nesting ---
Write-Host "[+] Checking group nesting depth..." -ForegroundColor Yellow

function Get-NestingDepth {
    param([string]$GroupDN, [int]$Depth = 0, [System.Collections.Generic.HashSet[string]]$Visited = $null)
    if (-not $Visited) { $Visited = [System.Collections.Generic.HashSet[string]]::new() }
    if ($Visited.Contains($GroupDN)) { return $Depth }
    $Visited.Add($GroupDN) | Out-Null
    $maxDepth = $Depth
    try {
        $members = (Get-ADGroup -Identity $GroupDN -Properties Members).Members
        foreach ($memberDN in $members) {
            try {
                $obj = Get-ADObject -Identity $memberDN
                if ($obj.objectClass -eq "group") {
                    $childDepth = Get-NestingDepth -GroupDN $memberDN -Depth ($Depth + 1) -Visited $Visited
                    if ($childDepth -gt $maxDepth) { $maxDepth = $childDepth }
                }
            } catch { }
        }
    } catch { }
    return $maxDepth
}

foreach ($group in $allGroups) {
    $hasNestedGroups = $false
    foreach ($memberDN in $group.Members) {
        try {
            $obj = Get-ADObject -Identity $memberDN -ErrorAction Stop
            if ($obj.objectClass -eq "group") { $hasNestedGroups = $true; break }
        } catch { }
    }
    if ($hasNestedGroups) {
        $depth = Get-NestingDepth -GroupDN $group.DistinguishedName
        if ($depth -ge $NestingDepthThreshold) {
            $groupFindings += [PSCustomObject]@{
                GroupName      = $group.Name
                SamAccountName = $group.SamAccountName
                Issue          = "DEEP_NESTING"
                Details        = "Nesting depth: $depth — hard to audit, priv escalation risk"
                MemberCount    = ($group.Members | Measure-Object).Count
                Scope          = $group.GroupScope
                ManagedBy      = if ($group.ManagedBy) { ($group.ManagedBy -split ',')[0] -replace 'CN=' } else { "NONE" }
                Created        = $group.WhenCreated.ToString("yyyy-MM-dd")
                OU             = ($group.DistinguishedName -replace '^CN=[^,]+,', '')
                Description    = $group.Description
                Severity       = "HIGH"
            }
        }
    }
}

# --- No Owner ---
Write-Host "[+] Flagging groups with no ManagedBy..." -ForegroundColor Yellow

$noOwner = $allGroups | Where-Object { -not $_.ManagedBy -and $_.SID.Value -notin $builtinGroupSIDs }
foreach ($group in $noOwner) {
    $groupFindings += [PSCustomObject]@{
        GroupName      = $group.Name
        SamAccountName = $group.SamAccountName
        Issue          = "NO_MANAGED_BY"
        Details        = "No owner assigned — accountability gap"
        MemberCount    = ($group.Members | Measure-Object).Count
        Scope          = $group.GroupScope
        ManagedBy      = "NONE"
        Created        = $group.WhenCreated.ToString("yyyy-MM-dd")
        OU             = ($group.DistinguishedName -replace '^CN=[^,]+,', '')
        Description    = $group.Description
        Severity       = "LOW"
    }
}

Write-Host "    Group findings: $($groupFindings.Count)" -ForegroundColor White
Export-Finding -Name "GroupHygiene" -Data $groupFindings


# ============================================================
# 5. PASSWORD & AUTH POLICY
# ============================================================
Write-Host "`n[========== PASSWORD POLICY ==========]" -ForegroundColor Cyan

# --- Domain Policy ---
Write-Host "[+] Checking domain password policy..." -ForegroundColor Yellow

$domainPolicy = Get-ADDefaultDomainPasswordPolicy
$policyFindings = @()

if ($domainPolicy.MinPasswordLength -lt 12) {
    $policyFindings += [PSCustomObject]@{
        Setting = "MinPasswordLength"; Current = $domainPolicy.MinPasswordLength
        Recommended = "12+"; Issue = "WEAK_MIN_LENGTH"
        Severity = if ($domainPolicy.MinPasswordLength -lt 8) { "CRITICAL" } else { "HIGH" }
    }
}
if (-not $domainPolicy.ComplexityEnabled) {
    $policyFindings += [PSCustomObject]@{
        Setting = "ComplexityEnabled"; Current = $false
        Recommended = "True"; Issue = "NO_COMPLEXITY"; Severity = "HIGH"
    }
}
if ($domainPolicy.LockoutThreshold -eq 0) {
    $policyFindings += [PSCustomObject]@{
        Setting = "LockoutThreshold"; Current = "0 (disabled)"
        Recommended = "5-10"; Issue = "NO_LOCKOUT"; Severity = "CRITICAL"
    }
} elseif ($domainPolicy.LockoutThreshold -gt 10) {
    $policyFindings += [PSCustomObject]@{
        Setting = "LockoutThreshold"; Current = $domainPolicy.LockoutThreshold
        Recommended = "5-10"; Issue = "HIGH_LOCKOUT_THRESHOLD"; Severity = "MEDIUM"
    }
}
if ($domainPolicy.ReversibleEncryptionEnabled) {
    $policyFindings += [PSCustomObject]@{
        Setting = "ReversibleEncryptionEnabled"; Current = $true
        Recommended = "False"; Issue = "REVERSIBLE_ENCRYPTION_DOMAIN"; Severity = "CRITICAL"
    }
}
if ($domainPolicy.PasswordHistoryCount -lt 12) {
    $policyFindings += [PSCustomObject]@{
        Setting = "PasswordHistoryCount"; Current = $domainPolicy.PasswordHistoryCount
        Recommended = "12-24"; Issue = "LOW_HISTORY"; Severity = "LOW"
    }
}

Write-Host "    Policy issues: $($policyFindings.Count)" -ForegroundColor White
Export-Finding -Name "PasswordPolicy" -Data $policyFindings

# --- FGPPs ---
Write-Host "[+] Checking Fine-Grained Password Policies..." -ForegroundColor Yellow

$fgppFindings = @()
try {
    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Properties `
        Name, Precedence, MinPasswordLength, ComplexityEnabled, `
        LockoutThreshold, MaxPasswordAge, AppliesTo
    foreach ($fgpp in $fgpps) {
        if ($fgpp.MinPasswordLength -lt 12 -or $fgpp.LockoutThreshold -eq 0) {
            $fgppFindings += [PSCustomObject]@{
                PolicyName = $fgpp.Name; Precedence = $fgpp.Precedence
                MinLength = $fgpp.MinPasswordLength; Complexity = $fgpp.ComplexityEnabled
                Lockout = $fgpp.LockoutThreshold; MaxAgeDays = $fgpp.MaxPasswordAge.Days
                AppliesTo = ($fgpp.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join "; "
                Issue = "FGPP_WEAK_SETTINGS"; Severity = "MEDIUM"
            }
        }
    }
} catch {
    Write-Host "    No FGPPs or insufficient permissions" -ForegroundColor Gray
}

if ($fgppFindings.Count -gt 0) { Export-Finding -Name "WeakFGPPs" -Data $fgppFindings }

# --- Dangerous Account Flags ---
Write-Host "[+] Scanning dangerous user account flags..." -ForegroundColor Yellow

$flagFindings = @()

foreach ($user in $allUsers) {
    $issues = @()

    if ($user.PasswordNeverExpires)              { $issues += "PWD_NEVER_EXPIRES" }
    if ($user.AllowReversiblePasswordEncryption) { $issues += "REVERSIBLE_ENCRYPTION" }
    if ($user.DoesNotRequirePreAuth)             { $issues += "ASREP_ROASTABLE" }
    if ($user.PasswordNotRequired)               { $issues += "PWD_NOT_REQUIRED" }
    if ($user.CannotChangePassword)              { $issues += "CANNOT_CHANGE_PWD" }

    if ($issues.Count -gt 0) {
        $inPrivGroup = $false
        foreach ($g in $user.MemberOf) {
            if ((($g -split ',')[0] -replace 'CN=') -in @("Domain Admins","Enterprise Admins","Administrators")) {
                $inPrivGroup = $true; break
            }
        }

        $sev = "MEDIUM"
        if ($issues -match "ASREP_ROASTABLE|REVERSIBLE_ENCRYPTION|PWD_NOT_REQUIRED") { $sev = "HIGH" }
        if ($inPrivGroup) { $sev = "CRITICAL" }

        $flagFindings += [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            Issues         = ($issues -join "; ")
            IsPrivileged   = $inPrivGroup
            HasSPN         = ($user.ServicePrincipalName.Count -gt 0)
            OU             = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
            Severity       = $sev
        }
    }
}

Write-Host "    Dangerous flags: $($flagFindings.Count)" -ForegroundColor White
Export-Finding -Name "AccountFlags" -Data $flagFindings


# ============================================================
# 6. ATTACK SURFACE
# ============================================================
Write-Host "`n[========== ATTACK SURFACE ==========]" -ForegroundColor Cyan

# --- Kerberoastable ---
Write-Host "[+] Finding Kerberoastable accounts..." -ForegroundColor Yellow

$kerbFindings = @()
$kerbUsers = $allUsers | Where-Object { $_.ServicePrincipalName.Count -gt 0 }

foreach ($user in $kerbUsers) {
    $inPrivGroup = $false
    foreach ($g in $user.MemberOf) {
        if ((($g -split ',')[0] -replace 'CN=') -match "^(Domain Admins|Enterprise Admins|Administrators|Account Operators|Backup Operators)$") {
            $inPrivGroup = $true; break
        }
    }
    $pwdAge = if ($user.PasswordLastSet) { [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays) } else { 99999 }

    $kerbFindings += [PSCustomObject]@{
        SamAccountName  = $user.SamAccountName
        SPNs            = ($user.ServicePrincipalName -join "; ")
        PasswordAgeDays = $pwdAge
        IsPrivileged    = $inPrivGroup
        OU              = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Description     = $user.Description
        Issue           = if ($inPrivGroup) { "KERBEROASTABLE_PRIVILEGED" } else { "KERBEROASTABLE" }
        Severity        = if ($inPrivGroup) { "CRITICAL" } elseif ($pwdAge -gt 365) { "HIGH" } else { "MEDIUM" }
        Remediation     = if ($inPrivGroup) { "Remove SPN or use gMSA; rotate password NOW" }
                          elseif ($pwdAge -gt 365) { "Rotate password; consider gMSA" }
                          else { "Monitor; consider gMSA migration" }
    }
}

Write-Host "    Kerberoastable: $($kerbFindings.Count)" -ForegroundColor White
Export-Finding -Name "Kerberoastable" -Data $kerbFindings

# --- AS-REP Roastable ---
Write-Host "[+] Finding AS-REP roastable accounts..." -ForegroundColor Yellow

$asrepFindings = @()
$asrepUsers = $allUsers | Where-Object { $_.DoesNotRequirePreAuth -eq $true }

foreach ($user in $asrepUsers) {
    $asrepFindings += [PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        PasswordAge    = if ($user.PasswordLastSet) { [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays) } else { "NEVER_SET" }
        OU             = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Issue          = "ASREP_ROASTABLE"
        Severity       = "HIGH"
        Remediation    = "Enable Kerberos pre-authentication; rotate password"
    }
}

if ($asrepFindings.Count -gt 0) { Export-Finding -Name "ASREPRoastable" -Data $asrepFindings }
Write-Host "    AS-REP roastable: $($asrepFindings.Count)" -ForegroundColor White

# --- LAPS Coverage ---
Write-Host "[+] Checking LAPS deployment..." -ForegroundColor Yellow

$lapsFindings = @()
$lapsDeployed = 0

foreach ($comp in $allComputers) {
    if (-not $comp.'ms-Mcs-AdmPwd') {
        $lapsFindings += [PSCustomObject]@{
            ComputerName    = $comp.Name
            OperatingSystem = $comp.OperatingSystem
            OU              = ($comp.DistinguishedName -replace '^CN=[^,]+,', '')
            Issue           = "NO_LAPS"
            Severity        = if ($comp.OperatingSystem -match "Server") { "HIGH" } else { "MEDIUM" }
            Remediation     = "Deploy LAPS GPO to this OU; ensure LAPS CSE installed"
        }
    } else {
        $lapsDeployed++
    }
}

$totalComps = $lapsDeployed + $lapsFindings.Count
$lapsPct = if ($totalComps -gt 0) { [math]::Round(($lapsDeployed / $totalComps) * 100, 1) } else { 0 }

Write-Host "    LAPS coverage: $lapsDeployed / $totalComps ($lapsPct%)" -ForegroundColor $(if ($lapsPct -lt 80) { "Red" } else { "Green" })
Export-Finding -Name "LAPS_Gaps" -Data $lapsFindings

# --- SIDHistory ---
Write-Host "[+] Checking SIDHistory..." -ForegroundColor Yellow

$sidFindings = @()
$sidHistUsers = $allUsers | Where-Object { $_.SIDHistory.Count -gt 0 }

foreach ($user in $sidHistUsers) {
    $sidFindings += [PSCustomObject]@{
        Name = $user.SamAccountName; Type = "User"
        SIDHistoryCount = $user.SIDHistory.Count
        SIDHistory = ($user.SIDHistory -join "; ")
        OU = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Issue = "HAS_SIDHISTORY"; Severity = "HIGH"
        Remediation = "Clear SIDHistory if migration complete; potential persistence vector"
    }
}

$sidHistComps = $allComputers | Where-Object { $_.SIDHistory.Count -gt 0 }
foreach ($comp in $sidHistComps) {
    $sidFindings += [PSCustomObject]@{
        Name = $comp.Name; Type = "Computer"
        SIDHistoryCount = $comp.SIDHistory.Count
        SIDHistory = ($comp.SIDHistory -join "; ")
        OU = ($comp.DistinguishedName -replace '^CN=[^,]+,', '')
        Issue = "HAS_SIDHISTORY"; Severity = "MEDIUM"
        Remediation = "Clear SIDHistory if migration complete"
    }
}

if ($sidFindings.Count -gt 0) { Export-Finding -Name "SIDHistory" -Data $sidFindings }
Write-Host "    SIDHistory entries: $($sidFindings.Count)" -ForegroundColor White

# --- Domain Trusts ---
Write-Host "[+] Enumerating domain trusts..." -ForegroundColor Yellow

$trustFindings = @()
$trusts = Get-ADTrust -Filter * -Properties TrustType, TrustDirection, TrustAttributes, WhenCreated -ErrorAction SilentlyContinue

foreach ($trust in $trusts) {
    $direction = switch ($trust.TrustDirection) { 1 {"Inbound"} 2 {"Outbound"} 3 {"Bidirectional"} default {"Unknown"} }
    $sidFilterOff = ($trust.TrustAttributes -band 4) -eq 0

    $trustFindings += [PSCustomObject]@{
        TrustedDomain = $trust.Target; Direction = $direction
        TrustType = $trust.TrustType; SIDFiltering = if ($sidFilterOff) { "DISABLED" } else { "Enabled" }
        Created = $trust.WhenCreated.ToString("yyyy-MM-dd")
        Issue = if ($sidFilterOff -and $direction -match "Inbound|Bidirectional") { "SID_FILTERING_DISABLED" } else { "TRUST_INFO" }
        Severity = if ($sidFilterOff) { "CRITICAL" } else { "INFO" }
        Remediation = if ($sidFilterOff) { "netdom trust /domain:$($trust.Target) /quarantine:yes" } else { "Review periodically" }
    }
}

if ($trustFindings.Count -gt 0) { Export-Finding -Name "DomainTrusts" -Data $trustFindings }
Write-Host "    Trusts: $($trustFindings.Count)" -ForegroundColor White

# --- Weak Kerberos ---
Write-Host "[+] Checking DES-only Kerberos accounts..." -ForegroundColor Yellow

$weakKerbFindings = @()
$desUsers = $allUsers | Where-Object { $_.UseDESKeyOnly -eq $true }

foreach ($user in $desUsers) {
    $weakKerbFindings += [PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        OU = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Issue = "DES_ONLY_KERBEROS"; Severity = "HIGH"
        Remediation = "Disable DES; ensure AES support"
    }
}

if ($weakKerbFindings.Count -gt 0) { Export-Finding -Name "WeakKerberos" -Data $weakKerbFindings }
Write-Host "    DES-only: $($weakKerbFindings.Count)" -ForegroundColor White


# ============================================================
# 7. REMOTE SERVICE CHECKS (Optional)
# ============================================================
if ($CheckRemoteServices) {
    Write-Host "`n[========== REMOTE SERVICES ==========]" -ForegroundColor Cyan

    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    $svcFindings = @()

    foreach ($dc in $dcs) {
        Write-Host "[+] Checking $dc..." -ForegroundColor Yellow

        # Print Spooler
        try {
            $spooler = Get-Service -Name Spooler -ComputerName $dc -ErrorAction Stop
            if ($spooler.Status -eq "Running") {
                $svcFindings += [PSCustomObject]@{
                    Server = $dc; Service = "Print Spooler"; Status = "RUNNING"
                    Issue = "PRINT_SPOOLER_ON_DC"; Severity = "CRITICAL"
                    Remediation = "Disable Print Spooler on DCs — PrintNightmare / coerce vector"
                }
            }
        } catch { Write-Warning "    Could not check Spooler on $dc" }

        # SMBv1
        try {
            $smb1 = Invoke-Command -ComputerName $dc -ScriptBlock {
                Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
            } -ErrorAction Stop
            if ($smb1.EnableSMB1Protocol) {
                $svcFindings += [PSCustomObject]@{
                    Server = $dc; Service = "SMBv1"; Status = "ENABLED"
                    Issue = "SMBV1_ENABLED"; Severity = "CRITICAL"
                    Remediation = "Set-SmbServerConfiguration -EnableSMB1Protocol `$false"
                }
            }
        } catch { Write-Warning "    Could not check SMBv1 on $dc" }
    }

    if ($svcFindings.Count -gt 0) { Export-Finding -Name "RemoteServices" -Data $svcFindings }
    Write-Host "    Remote service issues: $($svcFindings.Count)" -ForegroundColor White
}


# ============================================================
# EXECUTIVE SUMMARY
# ============================================================
Write-Host "`n[========== SUMMARY ==========]" -ForegroundColor Cyan

$csvFiles = Get-ChildItem -Path $OutputDir -Filter "*_${timestamp}.csv" -ErrorAction SilentlyContinue

$execSummary = @(
    [PSCustomObject]@{ Category="ENVIRONMENT"; Finding="Domain";          Value=$domainInfo.DNSRoot;    Severity="INFO" }
    [PSCustomObject]@{ Category="ENVIRONMENT"; Finding="Functional Level"; Value=$domainInfo.DomainMode;
        Severity = if ($domainInfo.DomainMode -match "2008|2003|2000") { "HIGH" } else { "INFO" }
    }
    [PSCustomObject]@{ Category="STALE";       Finding="Stale Users";           Value=$staleUsers.Count;        Severity = if ($staleUsers.Count -gt 50) {"HIGH"} elseif ($staleUsers.Count -gt 0) {"MEDIUM"} else {"INFO"} }
    [PSCustomObject]@{ Category="STALE";       Finding="Stale Computers";       Value=$staleComputers.Count;    Severity = if ($staleComputers.Count -gt 20) {"HIGH"} elseif ($staleComputers.Count -gt 0) {"MEDIUM"} else {"INFO"} }
    [PSCustomObject]@{ Category="STALE";       Finding="Disabled in Priv Groups"; Value=$disabledPriv.Count;    Severity = if ($disabledPriv.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="PRIVILEGE";   Finding="Privileged Members";     Value=$privMembers.Count;       Severity="INFO" }
    [PSCustomObject]@{ Category="PRIVILEGE";   Finding="Kerberoastable Admins";  Value=($privMembers | Where-Object Issue -eq "KERBEROASTABLE_ADMIN").Count; Severity = if (($privMembers | Where-Object Issue -eq "KERBEROASTABLE_ADMIN").Count -gt 0) {"CRITICAL"} else {"INFO"} }
    [PSCustomObject]@{ Category="PRIVILEGE";   Finding="AdminCount Orphans";     Value=$orphans.Count;           Severity = if ($orphans.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="DELEGATION";  Finding="Delegation Issues";      Value=$delegationFindings.Count; Severity = if (($delegationFindings | Where-Object Severity -eq "CRITICAL").Count -gt 0) {"CRITICAL"} else {"INFO"} }
    [PSCustomObject]@{ Category="GROUPS";      Finding="Empty Security Groups";  Value=($groupFindings | Where-Object Issue -eq "EMPTY_SECURITY_GROUP").Count; Severity="MEDIUM" }
    [PSCustomObject]@{ Category="GROUPS";      Finding="Orphaned SIDs";          Value=($groupFindings | Where-Object Issue -eq "ORPHANED_SID").Count; Severity="MEDIUM" }
    [PSCustomObject]@{ Category="GROUPS";      Finding="Deep Nesting";           Value=($groupFindings | Where-Object Issue -eq "DEEP_NESTING").Count; Severity = if (($groupFindings | Where-Object Issue -eq "DEEP_NESTING").Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="PASSWORD";    Finding="Policy Issues";          Value=$policyFindings.Count;    Severity = if (($policyFindings | Where-Object Severity -eq "CRITICAL").Count -gt 0) {"CRITICAL"} else {"MEDIUM"} }
    [PSCustomObject]@{ Category="PASSWORD";    Finding="Dangerous Account Flags"; Value=$flagFindings.Count;     Severity = if ($flagFindings.Count -gt 20) {"HIGH"} elseif ($flagFindings.Count -gt 0) {"MEDIUM"} else {"INFO"} }
    [PSCustomObject]@{ Category="ATTACK";      Finding="Kerberoastable SPNs";    Value=$kerbFindings.Count;      Severity = if (($kerbFindings | Where-Object Severity -eq "CRITICAL").Count -gt 0) {"CRITICAL"} elseif ($kerbFindings.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="ATTACK";      Finding="AS-REP Roastable";       Value=$asrepFindings.Count;     Severity = if ($asrepFindings.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="ATTACK";      Finding="LAPS Coverage %";        Value="$lapsPct%";              Severity = if ($lapsPct -lt 50) {"CRITICAL"} elseif ($lapsPct -lt 80) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="ATTACK";      Finding="SIDHistory Entries";     Value=$sidFindings.Count;       Severity = if ($sidFindings.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="ATTACK";      Finding="Domain Trusts";          Value=$trustFindings.Count;     Severity="INFO" }
    [PSCustomObject]@{ Category="ATTACK";      Finding="DES-Only Kerberos";      Value=$weakKerbFindings.Count;  Severity = if ($weakKerbFindings.Count -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="TOTALS";      Finding="Critical Findings";      Value=$script:totalCritical;    Severity = if ($script:totalCritical -gt 0) {"CRITICAL"} else {"INFO"} }
    [PSCustomObject]@{ Category="TOTALS";      Finding="High Findings";          Value=$script:totalHigh;        Severity = if ($script:totalHigh -gt 0) {"HIGH"} else {"INFO"} }
    [PSCustomObject]@{ Category="TOTALS";      Finding="Medium Findings";        Value=$script:totalMedium;      Severity="INFO" }
    [PSCustomObject]@{ Category="TOTALS";      Finding="Low Findings";           Value=$script:totalLow;         Severity="INFO" }
    [PSCustomObject]@{ Category="TOTALS";      Finding="Reports Generated";      Value=$csvFiles.Count;          Severity="INFO" }
)

$totalElapsed = (Get-Date) - $totalStart
$execSummary += [PSCustomObject]@{ Category="TOTALS"; Finding="Audit Duration (sec)"; Value=[math]::Round($totalElapsed.TotalSeconds, 1); Severity="INFO" }

$execCsv = Join-Path $OutputDir "ExecutiveSummary_$timestamp.csv"
$execSummary | Export-Csv -Path $execCsv -NoTypeInformation

Write-Host @"

    +==================================================+
    |              AUDIT COMPLETE                       |
    +--------------------------------------------------+
    |  CRITICAL:  $($script:totalCritical.ToString().PadLeft(5))                               |
    |  HIGH:      $($script:totalHigh.ToString().PadLeft(5))                               |
    |  MEDIUM:    $($script:totalMedium.ToString().PadLeft(5))                               |
    |  LOW:       $($script:totalLow.ToString().PadLeft(5))                               |
    |                                                  |
    |  Reports: $($csvFiles.Count.ToString().PadLeft(2)) CSVs in $OutputDir              |
    |  Duration: $([math]::Round($totalElapsed.TotalSeconds, 1).ToString().PadLeft(6))s                           |
    +==================================================+

"@ -ForegroundColor $(if ($script:totalCritical -gt 0) { "Red" } elseif ($script:totalHigh -gt 0) { "Yellow" } else { "Green" })

Write-Host "[*] Executive Summary -> $execCsv" -ForegroundColor Cyan
Write-Host "[*] All reports in $OutputDir`n" -ForegroundColor Cyan
