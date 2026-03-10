# sentinel-kql-detections

A collection of custom KQL queries built for Microsoft Sentinel targeting real-world attack patterns. These are written from hands-on experience working in a hybrid IT/Security role — managing CrowdStrike, Microsoft 365, Entra ID, and email security daily. Each query maps to a MITRE ATT&CK technique and is built around log sources you'll actually have in a standard M365/Azure environment.

---

## Table of Contents

1. [MFA Fatigue / Failed MFA Spike](#1-mfa-fatigue--failed-mfa-spike)
2. [Impossible Travel Detection](#2-impossible-travel-detection)
3. [Brute Force Login Attempts](#3-brute-force-login-attempts)
4. [New Admin Role Assignment](#4-new-admin-role-assignment)
5. [Suspicious Inbox Rule - External Forwarding](#5-suspicious-inbox-rule---external-forwarding)
6. [Privilege Escalation via Azure AD Role](#6-privilege-escalation-via-azure-ad-role)
7. [Mass File Download - Potential Exfiltration](#7-mass-file-download---potential-exfiltration)
8. [Service Principal Abuse](#8-service-principal-abuse)
9. [Suspicious PowerShell Execution](#9-suspicious-powershell-execution)
10. [Lateral Movement - Pass the Hash Indicator](#10-lateral-movement---pass-the-hash-indicator)
11. [Risky Sign-In from Anonymous IP](#11-risky-sign-in-from-anonymous-ip)
12. [User Account Created and Immediately Used](#12-user-account-created-and-immediately-used)
13. [Mass File Deletion - Potential Ransomware](#13-mass-file-deletion---potential-ransomware)
14. [Disabled MFA for a User Account](#14-disabled-mfa-for-a-user-account)
15. [Suspicious OAuth Application Consent](#15-suspicious-oauth-application-consent)

---

## 1. MFA Fatigue / Failed MFA Spike

**MITRE ATT&CK:** T1621 — Multi-Factor Authentication Request Generation

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50074" or ResultType == "50076"
| summarize FailedMFACount = count() by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedMFACount >= 10
| order by FailedMFACount desc
```

**What this does:**
This catches MFA fatigue attacks — where an attacker who already has a user's password hammers them with MFA push notifications hoping they'll just approve it to make it stop. If someone is hitting 10+ MFA failures in a 10-minute window, that's not a user fat-fingering their phone — something is wrong. This is one of the first things I'd want alerted on in any environment running Entra ID.

---

## 2. Impossible Travel Detection

**MITRE ATT&CK:** T1078 — Valid Accounts

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project UserPrincipalName, TimeGenerated, Location, IPAddress
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevLocation = prev(Location, 1),
         PrevTime = prev(TimeGenerated, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| where Location != PrevLocation
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60
| project UserPrincipalName, PrevLocation, Location, TimeDiffMinutes, IPAddress
```

**What this does:**
If a user signs in from Chicago and then from another country within the same hour, one of those sign-ins isn't legitimate. Impossible travel is a classic indicator of account compromise — especially when credentials get phished and immediately handed off. This query surfaces those back-to-back sign-ins where the geography doesn't add up.

---

## 3. Brute Force Login Attempts

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 15m)
| where FailedAttempts >= 15
| order by FailedAttempts desc
```

**What this does:**
Tracks repeated failed logins against the same account in a short window. The `DistinctIPs` count is the useful part here — if failures are coming from multiple IPs, you're likely looking at a distributed spray attack rather than a user who forgot their password. Threshold is set at 15 but you'd tune that based on your environment's baseline.

---

## 4. New Admin Role Assignment

**MITRE ATT&CK:** T1098 — Account Manipulation

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleAssigned = tostring(TargetResources[0].displayName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleAssigned contains "Admin"
| project TimeGenerated, InitiatedBy, TargetUser, RoleAssigned
```

**What this does:**
Any time a privileged role gets assigned in Entra ID, you want to know about it immediately. Attackers who get into a tenant will almost always try to escalate to Global Admin or a similar role to maintain persistence. This also helps with least-privilege auditing — you'd be surprised how often admin roles get handed out without a ticket or approval.

---

## 5. Suspicious Inbox Rule - External Forwarding

**MITRE ATT&CK:** T1114.003 — Email Collection: Email Forwarding Rule

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation == "New-InboxRule" or Operation == "Set-InboxRule"
| extend RuleParameters = tostring(Parameters)
| where RuleParameters has "ForwardTo" or RuleParameters has "RedirectTo"
| where RuleParameters !has "@yourdomain.com"
| project TimeGenerated, UserId, ClientIP, RuleParameters
```

**What this does:**
One of the first things a threat actor does after compromising a mailbox is set up a silent forwarding rule to an external address so they can monitor communications without the user noticing. This query catches those — especially rules that route mail outside your domain. Replace `@yourdomain.com` with your actual tenant domain before running.

---

## 6. Privilege Escalation via Azure AD Role

**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("Add eligible member to role", "Add member to role in PIM")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, Target, Role
| where Role has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
```

**What this does:**
This specifically watches for the highest-risk role assignments in Azure AD. Global Admin, Privileged Role Admin, and Security Admin are the crown jewels — if any of those get assigned outside a change window or by an unexpected account, that needs immediate investigation. PIM activity is included here too since attackers will try to abuse eligible assignments if they can.

---

## 7. Mass File Download - Potential Exfiltration

**MITRE ATT&CK:** T1530 — Data from Cloud Storage

```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation == "FileDownloaded"
| summarize DownloadCount = count() by UserId, ClientIP, bin(TimeGenerated, 15m)
| where DownloadCount >= 50
| order by DownloadCount desc
```

**What this does:**
50+ file downloads in 15 minutes is not normal user behavior. This catches bulk data staging — either a compromised account grabbing everything before exfil, or an insider doing the same. The threshold should be tuned to your org's baseline. If your users routinely sync large SharePoint libraries you'll want to filter those out by ClientIP or user group.

---

## 8. Service Principal Abuse

**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add service principal credentials"
    or OperationName == "Update service principal"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, AppName, OperationName
```

**What this does:**
Service principals are a blind spot in a lot of environments. Attackers who get into a tenant will add credentials to an existing service principal so they have a persistent backdoor that doesn't look like a user account. If credentials are being added to a service principal outside of a normal deployment window, that warrants a look. Cross-reference the Actor field against your known admin accounts.

---

## 9. Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4104
| where ScriptBlockText has_any (
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "EncodedCommand",
    "FromBase64String",
    "bypass",
    "hidden",
    "-nop"
)
| project TimeGenerated, Computer, Account, ScriptBlockText
| order by TimeGenerated desc
```

**What this does:**
These are the PowerShell flags that show up in almost every post-exploitation framework — Cobalt Strike, PowerShell Empire, you name it. Encoded commands and bypassed execution policies are not something normal users or most legitimate scripts need. EventID 4104 requires Script Block Logging to be enabled via GPO — if your environment doesn't have that turned on yet, that's worth fixing before deploying this query.

---

## 10. Lateral Movement - Pass the Hash Indicator

**MITRE ATT&CK:** T1550.002 — Use Alternate Authentication Material: Pass the Hash

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where WorkstationName != Computer
| summarize count() by Account, WorkstationName, Computer, IpAddress
| where count_ > 5
| order by count_ desc
```

**What this does:**
Pass the Hash abuses NTLM authentication to move laterally without ever knowing the plaintext password. Network logons (Type 3) using NTLM where the source workstation doesn't match the target is a pattern worth tracking. This won't catch every PtH attempt but it surfaces the noisy ones — and if you're seeing the same account authenticating across multiple machines via NTLM, that's worth digging into.

---

## 11. Risky Sign-In from Anonymous IP

**MITRE ATT&CK:** T1090 — Proxy

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where RiskEventTypes has "anonymizedIPAddress"
    or NetworkLocationDetails has "anonymousProxy"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

**What this does:**
Successful sign-ins from Tor exit nodes or anonymous proxies are a red flag regardless of whether MFA passed. Legitimate users don't typically authenticate from anonymized infrastructure. This is especially worth watching for service accounts or admin accounts — if you see one of those coming through an anonymous IP, treat it as compromised until proven otherwise.

---

## 12. User Account Created and Immediately Used

**MITRE ATT&CK:** T1136.003 — Create Account: Cloud Account

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add user"
| extend NewUser = tostring(TargetResources[0].userPrincipalName)
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend CreationTime = TimeGenerated
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == 0
    | project SigninTime = TimeGenerated, UserPrincipalName
) on $left.NewUser == $right.UserPrincipalName
| extend MinutesUntilLogin = datetime_diff('minute', SigninTime, CreationTime)
| where MinutesUntilLogin between (0 .. 30)
| project CreationTime, SigninTime, NewUser, CreatedBy, MinutesUntilLogin
```

**What this does:**
A brand new account signing in within 30 minutes of being created is unusual — especially outside of business hours. Attackers who have admin access will create backdoor accounts and use them almost immediately. This query correlates account creation events in AuditLogs against successful sign-ins to catch that behavior early.

---

## 13. Mass File Deletion - Potential Ransomware

**MITRE ATT&CK:** T1485 — Data Destruction

```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation == "FileDeleted" or Operation == "FileRecycled"
| summarize DeletionCount = count() by UserId, ClientIP, bin(TimeGenerated, 10m)
| where DeletionCount >= 100
| order by DeletionCount desc
```

**What this does:**
Ransomware and destructive attacks often start with bulk deletion or overwriting of files before dropping the ransom note. 100 deletions in 10 minutes from a single user is a strong signal — normal users don't operate at that speed. Pair this alert with your endpoint detection tool for correlated context on what process is driving the deletions.

---

## 14. Disabled MFA for a User Account

**MITRE ATT&CK:** T1556 — Modify Authentication Process

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Update user"
| extend ChangedProperties = tostring(TargetResources[0].modifiedProperties)
| where ChangedProperties has "StrongAuthenticationRequirement"
| extend AffectedUser = tostring(TargetResources[0].userPrincipalName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ModifiedBy, AffectedUser, ChangedProperties
```

**What this does:**
If an attacker gains admin access, one of their first moves will be to disable MFA on an account they control so they can come back without getting blocked. This query tracks any changes to MFA configuration on user accounts. It's also useful for compliance — in some environments MFA should never be disabled without a documented exception, and this gives you the audit trail.

---

## 15. Suspicious OAuth Application Consent

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material: Application Access Token

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(AdditionalDetails)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All")
| project TimeGenerated, ConsentedBy, AppName, Permissions
```

**What this does:**
OAuth phishing is a technique where attackers trick users into granting a malicious third-party app access to their mailbox or files — no password needed. The dangerous permissions are the ones that let an app read mail or write to files on behalf of the user. This query catches consent events where broad permissions were granted so you can review whether those apps are legitimate.

---

## Environment Notes

- Log sources used: `SigninLogs`, `AuditLogs`, `OfficeActivity`, `SecurityEvent`
- Requires Microsoft Sentinel with M365 and Azure AD diagnostic settings connected
- Some queries require additional features enabled (e.g., Script Block Logging for Query 9, Identity Protection for Query 11)
- Thresholds throughout should be tuned to your environment's baseline before production use

---

*Built by Jay Rao | [LinkedIn](https://www.linkedin.com/in/jayrao-/) | Cybersecurity & IT Analyst*
