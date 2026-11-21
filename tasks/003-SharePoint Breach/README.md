# Day 3: SharePoint Breach – Security Assessment & Detection

## 1. Overview
This exercise simulates a SharePoint security breach, demonstrating how attackers may exploit authentication weaknesses, establish persistence, access sensitive information, and attempt to hide their activities.

The objective was to understand the attack lifecycle, analyse each phase, identify security weaknesses, and explore defensive detection and remediation techniques.

## 2. Lab Environment
- **Platform:** Kali Linux
- **Target:** Simulated SharePoint Environment
- **Focus:** Web Application Security, OAuth, XSS, Data Exfiltration and Incident Response
- **Tools:** 
  - Legba
  - Atomic Operator
  - XSStrike
  - curl
  - jq
  - tar
  - GPG

## 3. Attack Phases

### Phase 1 – Reconnaissance & Password Spraying
- Tested username and password combinations against the simulated SharePoint environment.
- Identified two valid credential combinations.
- Understood password spraying and credential-based attacks.

### Phase 2 – OAuth Authentication Bypass
- Simulated an OAuth authentication bypass.
- Obtained an access token according to the lab output.
- Observed access being granted as the System Account.

### Phase 3 – Persistence & XSS
- Used XSStrike to test for potential Cross-Site Scripting (XSS).
- Identified a potentially vulnerable `$filter` parameter.
- Explored a reported WAF bypass.
- Attempted OAuth application registration using the obtained token.
- Application name: `MaintenanceApp`.

### Phase 4 – Data Exfiltration
- Enumerated files in the SharePoint HR Documents folder.
- Identified employee contracts and salary reports.
- Explored file archiving using TAR.
- Encrypted the archive using GPG.
- Simulated transferring the encrypted archive to an external server.

### Phase 5 – Cover & Detection
- Examined an attempt to clear SharePoint audit logs.
- Understood how attackers may attempt to remove evidence.
- Studied the importance of audit logging and independent log storage.

## 4. Key Learning Outcomes
- Understanding password spraying attacks.
- Understanding OAuth authentication and access tokens.
- Learning Cross-Site Scripting (XSS) concepts.
- Understanding Web Application Firewalls (WAF).
- Learning application-based persistence concepts.
- Understanding data enumeration and exfiltration.
- Learning file compression and encryption.
- Understanding audit log tampering.
- Identifying suspicious activities from a SOC perspective.

## 5. Detection & Defensive Recommendations
- Monitor unusual authentication attempts.
- Investigate suspicious OAuth token activity.
- Review unexpected application registrations and permissions.
- Monitor suspicious SharePoint API requests.
- Implement endpoint and network monitoring.
- Monitor bulk file access and unusual external transfers.
- Protect audit logs from unauthorized deletion.
- Integrate logs with a centralized SIEM platform.
- Apply relevant security patches and access controls.

## 6. Project Documentation

The following files contain the detailed technical work and supporting documentation:

| File | Description |
|---|---|
| SharePoint_Breach_Executive_CISO_Report.docx | Executive-level security assessment |
| SharePoint_Breach_Technical_PoC_with_Screenshots.docx | Technical walkthrough with screenshots |
| SharePoint_Defensive_Detection_PoC.py | Defensive detection demonstration |

## 7. Important Note
This exercise was performed in a simulated lab environment for cybersecurity learning and defensive security research.

The reported tool outputs represent lab results and should not be treated as independent verification of a real-world vulnerability or successful compromise.

---

**Repository:** GraySentinel-DSOU  
**Activity:** Day 3 – SharePoint Breach  
**Focus:** Attack Simulation, Security Analysis & Defensive Detection
