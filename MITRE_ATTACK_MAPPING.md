# MITRE ATT&CK Mapping Reference

## Detection Rules → MITRE ATT&CK Coverage

This document maps all detection rules in the lab to MITRE ATT&CK tactics and techniques.

---

## Overview

**Total Techniques Covered:** 9  
**Total Tactics Covered:** 7  
**Detection Rules:** 9+  

### Coverage by Tactic

| Tactic | Techniques Covered | Detection Rules |
|--------|-------------------|-----------------|
| Initial Access | 1 | Impossible Travel |
| Execution | 1 | Suspicious PowerShell |
| Credential Access | 3 | Mimikatz, Brute Force (2x), AWS Abuse |
| Discovery | 1 | Network Scanning |
| Lateral Movement | 1 | PsExec |
| Privilege Escalation | 1 | AWS IAM Changes |

---

## Detailed Mapping

### 1. Initial Access

#### T1078: Valid Accounts
**Detection Rule:** `detect_impossible_travel`  
**Description:** User authenticates from two geographically distant locations within impossible timeframe  
**Data Source:** Okta authentication logs  
**Severity:** HIGH  

**Detection Logic:**
- Track user login locations over time
- Calculate time between logins from different countries
- Flag if < 1 hour travel time between distant locations

**Example Alert:**
```
User alice@company.com logged in from Russia (Moscow) 
only 15 minutes after logging in from United States (New York)
```

**False Positive Scenarios:**
- VPN usage
- Shared accounts
- Clock synchronization issues

**Tuning Recommendations:**
- Whitelist known VPN IPs
- Increase minimum distance threshold
- Add user role exceptions (executives with dual offices)

---

### 2. Execution

#### T1059.001: PowerShell
**Detection Rule:** `detect_suspicious_powershell`  
**Description:** Detects obfuscated, encoded, or suspicious PowerShell command execution  
**Data Source:** Sysmon process creation (EventID 1)  
**Severity:** HIGH  

**Detection Logic:**
- Flag PowerShell with `-encodedcommand` or `-enc` parameter
- Flag hidden window execution (`-windowstyle hidden`)
- Flag download strings (IEX, Invoke-Expression, DownloadString)
- Flag suspicious execution from unusual parent processes

**Example Alert:**
```
Suspicious PowerShell Execution: Base64 encoded PowerShell command
Process: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...
```

**False Positive Scenarios:**
- Legitimate admin scripts
- Software deployment tools (SCCM, Intune)
- Automation frameworks

**Tuning Recommendations:**
- Whitelist known script hashes
- Exclude specific admin users
- Cross-reference with change management tickets

---

### 3. Credential Access

#### T1003.001: OS Credential Dumping - LSASS Memory
**Detection Rule:** `detect_mimikatz`  
**Description:** Detects execution of Mimikatz or other credential dumping tools  
**Data Source:** Sysmon process creation (EventID 1)  
**Severity:** CRITICAL  

**Detection Logic:**
- Match process name: mimikatz.exe, procdump.exe, dumpert.exe
- Match command line patterns: sekurlsa::logonpasswords, lsadump::sam
- Match suspicious LSASS memory access patterns

**Example Alert:**
```
Mimikatz Credential Dumping Detected
Process: mimikatz.exe sekurlsa::logonpasswords
Host: WORKSTATION-042
User: admin_backup
```

**False Positive Scenarios:**
- Security tool testing (authorized penetration tests)
- Training environments
- Security research

**Tuning Recommendations:**
- Require additional context (parent process, user role)
- Cross-check with scheduled pen test calendar
- Alert on ANY execution regardless (critical severity)

---

#### T1110: Brute Force
**Detection Rule:** `detect_okta_bruteforce`  
**Description:** Detects password brute force attempts via multiple failed logins  
**Data Source:** Okta authentication logs  
**Severity:** HIGH  

**Detection Logic:**
- Count failed login attempts per user per source IP
- Threshold: 5+ failures within 10 minutes
- Escalate to CRITICAL if 10+ failures

**Example Alert:**
```
Okta Brute Force Attack Detected
User: ceo@company.com
Source IP: 192.168.1.100
Failed Attempts: 12
Duration: 8.5 minutes
```

**False Positive Scenarios:**
- User forgot password
- Password manager sync issues
- Multiple users behind NAT

**Tuning Recommendations:**
- Adjust threshold based on environment (5-10 typical)
- Whitelist internal IPs with lower threshold
- Combine with account lockout policies

---

#### T1110.001: Password Guessing
**Detection Rule:** `detect_windows_bruteforce`  
**Description:** Detects Windows logon brute force via Event ID 4625 (failed logon)  
**Data Source:** Windows Security Event Logs  
**Severity:** HIGH  

**Detection Logic:**
- Count Event ID 4625 per user per host
- Threshold: 10+ failures within 5 minutes
- Focus on remote logon types (3, 10)

**Example Alert:**
```
Windows Brute Force Attack
User: Administrator
Host: SERVER-01
Source IP: 10.0.50.100
Failed Logons: 15
Logon Type: Remote Interactive (RDP)
```

**False Positive Scenarios:**
- Service accounts with incorrect passwords
- Scheduled tasks with wrong credentials
- Desktop support troubleshooting

**Tuning Recommendations:**
- Exclude specific service accounts
- Different thresholds for servers vs. workstations
- Correlate with successful logon after failures (actual compromise)

---

#### T1078.004: Cloud Accounts
**Detection Rule:** `detect_aws_api_failures`  
**Description:** Detects excessive AWS API failures indicating credential abuse  
**Data Source:** AWS CloudTrail  
**Severity:** MEDIUM  

**Detection Logic:**
- Count failed API calls per user per service
- Threshold: 15+ failures within 10 minutes
- Focus on specific error codes: AccessDenied, UnauthorizedOperation

**Example Alert:**
```
Excessive AWS API Failures
User: devops-user
Source IP: 203.0.113.50
Service: iam.amazonaws.com
Failed API Calls: 23
Error: AccessDenied
```

**False Positive Scenarios:**
- IAM permission changes (legitimate)
- Development/testing with insufficient permissions
- Misconfigurations

**Tuning Recommendations:**
- Lower threshold for sensitive services (IAM, KMS)
- Exclude known development/test accounts
- Alert on successful calls after many failures

---

### 4. Discovery

#### T1046: Network Service Scanning
**Detection Rule:** `detect_network_scanning`  
**Description:** Detects reconnaissance via network scanning  
**Data Source:** Sysmon network connection (EventID 3)  
**Severity:** MEDIUM  

**Detection Logic:**
- Count unique destination IPs per process per host
- Threshold: 20+ unique IPs within 1 minute
- Escalate if scanning common service ports (22, 445, 3389)

**Example Alert:**
```
Network Scanning Activity Detected
Host: WORKSTATION-025
Process: nmap.exe
Unique Destinations: 45
Total Connections: 200
Ports: 22, 445, 3389, 135
```

**False Positive Scenarios:**
- Network monitoring tools
- Vulnerability scanners (authorized)
- Legitimate network discovery (SCCM, monitoring)

**Tuning Recommendations:**
- Whitelist known scanner IPs/hosts
- Different thresholds for servers vs. workstations
- Focus on suspicious ports only

---

### 5. Lateral Movement

#### T1570: Lateral Tool Transfer
**Detection Rule:** `detect_psexec`  
**Description:** Detects use of PsExec or similar tools for lateral movement  
**Data Source:** Sysmon process creation (EventID 1)  
**Severity:** HIGH  

**Detection Logic:**
- Match process name: psexec.exe, psexesvc.exe, paexec.exe
- Match command line with remote host indicators
- Flag if executed by non-admin users

**Example Alert:**
```
PsExec Lateral Movement Detected
Process: psexec.exe \\SERVER-02 -u admin cmd.exe
Host: WORKSTATION-010
User: john.doe
Target: SERVER-02
```

**False Positive Scenarios:**
- IT admin legitimate remote management
- Deployment tools using PsExec
- Scheduled maintenance scripts

**Tuning Recommendations:**
- Whitelist known admin accounts
- Require approval workflow for PsExec use
- Cross-reference with change management

---

### 6. Privilege Escalation

#### T1098: Account Manipulation
**Detection Rule:** `detect_aws_privilege_escalation`  
**Description:** Detects high-risk IAM changes in AWS  
**Data Source:** AWS CloudTrail  
**Severity:** CRITICAL  

**Detection Logic:**
- Match high-risk event names:
  - CreateAccessKey
  - AttachUserPolicy, AttachRolePolicy
  - PutUserPolicy, PutRolePolicy
  - CreateUser, CreateLoginProfile
- Flag any DeleteTrail or StopLogging (defense evasion)

**Example Alert:**
```
AWS Privilege Escalation Attempt
Event: AttachUserPolicy
User: contractor-user
Target: AdminAccess policy attached to junior-dev user
Region: us-east-1
Source IP: 198.51.100.25
```

**False Positive Scenarios:**
- Legitimate IAM changes by security team
- Infrastructure-as-Code deployments (Terraform)
- Automated provisioning systems

**Tuning Recommendations:**
- Whitelist known automation service accounts
- Require MFA for sensitive IAM operations
- Alert on any change outside business hours

---

## Detection Coverage Matrix

### ATT&CK Tactics (Coverage: 6/14)

| Tactic | Status | Notes |
|--------|--------|-------|
| ✅ Initial Access | Covered | T1078 |
| ❌ Execution | Partial | T1059.001 only |
| ❌ Persistence | Not Covered | Add registry/startup detection |
| ✅ Privilege Escalation | Covered | T1098 (cloud) |
| ❌ Defense Evasion | Not Covered | Add log clearing, AV disable |
| ✅ Credential Access | Covered | T1003, T1110 |
| ✅ Discovery | Covered | T1046 |
| ✅ Lateral Movement | Covered | T1570 |
| ❌ Collection | Not Covered | Add data staging detection |
| ❌ Command and Control | Not Covered | Add C2 beacon detection |
| ❌ Exfiltration | Not Covered | Add large data transfer detection |
| ❌ Impact | Not Covered | Add ransomware detection |

### Recommended Additional Coverage

#### High Priority (Add Next)

**Persistence: T1547.001 - Registry Run Keys**
```sql
-- Detect registry autorun modifications
SELECT *
FROM silver_sysmon_registry
WHERE 
  registry_path LIKE '%\\CurrentVersion\\Run%'
  OR registry_path LIKE '%\\CurrentVersion\\RunOnce%'
```

**Defense Evasion: T1070.001 - Clear Windows Event Logs**
```sql
-- Detect event log clearing (Windows Event ID 1102)
SELECT *
FROM silver_windows_security
WHERE event_id = 1102
```

**Command and Control: T1071.001 - Web Protocols**
```sql
-- Detect suspicious outbound connections
SELECT *
FROM silver_sysmon_network
WHERE 
  destination_port IN (80, 443, 8080)
  AND process_name NOT IN ('chrome.exe', 'firefox.exe', 'teams.exe')
  AND connection_count > 100 -- Beaconing behavior
```

---

## MITRE ATT&CK Navigator Export

For visualizing coverage, export this JSON to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):

```json
{
  "name": "Databricks Security Detection Lab Coverage",
  "versions": {
    "attack": "13",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Detection coverage for Databricks Security Lab",
  "techniques": [
    {
      "techniqueID": "T1078",
      "color": "#00FF00",
      "comment": "Impossible Travel detection"
    },
    {
      "techniqueID": "T1059.001",
      "color": "#00FF00",
      "comment": "Suspicious PowerShell detection"
    },
    {
      "techniqueID": "T1003.001",
      "color": "#00FF00",
      "comment": "Mimikatz detection"
    },
    {
      "techniqueID": "T1110",
      "color": "#00FF00",
      "comment": "Brute force detection (Okta + Windows)"
    },
    {
      "techniqueID": "T1110.001",
      "color": "#00FF00",
      "comment": "Windows brute force"
    },
    {
      "techniqueID": "T1078.004",
      "color": "#00FF00",
      "comment": "AWS API abuse detection"
    },
    {
      "techniqueID": "T1046",
      "color": "#00FF00",
      "comment": "Network scanning detection"
    },
    {
      "techniqueID": "T1570",
      "color": "#00FF00",
      "comment": "PsExec lateral movement"
    },
    {
      "techniqueID": "T1098",
      "color": "#00FF00",
      "comment": "AWS privilege escalation"
    }
  ],
  "gradient": {
    "colors": ["#ffffff", "#00ff00"],
    "minValue": 0,
    "maxValue": 1
  }
}
```

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Sigma Rules (ATT&CK Tagged)](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

## Gap Analysis

### Critical Gaps
1. **No Ransomware Detection** - Add T1486 (Data Encrypted for Impact)
2. **No C2 Detection** - Add network beacon analysis
3. **No Exfiltration Detection** - Add large data transfer rules

### Medium Priority Gaps
4. **Limited Persistence Coverage** - Add registry, scheduled tasks
5. **No Defense Evasion** - Add log manipulation, AV disable
6. **No Collection** - Add data staging, clipboard capture

### Next Lab Enhancement
Consider adding:
- **Lab 05: Advanced Techniques** - ML-based anomaly detection
- **Lab 06: Purple Team** - Simulate attacks, validate detections
- **Lab 07: Response Automation** - Auto-remediation workflows

---

**Last Updated:** 2024-10-24  
**Version:** 1.0

