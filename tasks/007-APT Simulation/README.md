# Day 7 – Week 1 APT Capstone | China-Nexus APT Simulation

> **GraySentinel | Purple Team Lab | Threat Detection & Incident Response**

## Overview

This project represents a Week 1 cybersecurity capstone focused on simulating, investigating and detecting a multi-stage Advanced Persistent Threat (APT) campaign in a controlled lab environment.

The exercise follows a simulated China-nexus threat actor campaign that chains multiple vulnerability scenarios into a broader attack lifecycle. The objective was to practice the complete security operations workflow — from threat intelligence and attack simulation to SIEM detection, incident investigation, IOC enrichment and MITRE ATT&CK mapping.

This lab combines offensive simulation concepts with defensive monitoring and incident-response workflows to understand how SOC teams detect, correlate, investigate and document sophisticated attack activity.

---

## Objectives

- Perform threat actor profiling and vulnerability reconnaissance.
- Analyze a simulated multi-CVE attack chain.
- Emulate multi-stage adversary activity in a controlled lab.
- Review generated security telemetry through Wazuh and Elastic.
- Pivot on Indicators of Compromise (IOCs).
- Develop and validate detection logic.
- Create and enrich an incident case using TheHive and Cortex.
- Map observed simulation activity to MITRE ATT&CK.
- Generate technical and executive-level incident documentation.

---

## Lab Architecture & Tooling

| Tool | Purpose |
|---|---|
| Threat Intelligence CLI | Threat actor profiling and CVE enrichment |
| Atomic Operator | Controlled atomic-test simulation |
| AdaptixC2 simulator | Simulated adversary lifecycle replay |
| Wazuh | Security monitoring and detection |
| Elastic Stack | Log querying and event correlation |
| TheHive | Incident management and case tracking |
| Cortex | IOC enrichment and analysis |
| MITRE ATT&CK | Adversary technique mapping |
| ATT&CK Navigator | Visualization of technique coverage |
| Python | Offline defensive detection PoC |

---

## Attack Chain Scenario

The lab modeled a sequential multi-stage campaign.

| Stage | Scenario | CVE Label | MITRE Mapping shown in lab |
|---|---|---|---|
| 1 | Edge Gateway Exploitation | CVE-2026-59310 | T1190 – Exploit Public-Facing Application |
| 2 | Authentication / Token Abuse | CVE-2026-33824 | T1078 – Valid Accounts (lab mapping) |
| 3 | Update-Agent Command Injection | CVE-2026-65400 | T1059 – Command and Scripting Interpreter (lab mapping) |

The simulation subsequently displayed additional adversary lifecycle stages, including:

- Credential access
- Persistence
- Lateral movement
- Command and control
- Data exfiltration

**Note:** CVE descriptions, threat attribution and mappings in this project are scenario-generated lab content and should not be interpreted as independently verified vulnerability or attribution claims.

---

## Phase 1 – Threat Intelligence & CVE Reconnaissance

The first phase focused on understanding the simulated threat actor and the vulnerability chain.

Activities included:

- Threat actor profiling.
- CVE reconnaissance and contextual enrichment.
- Review of vulnerability severity and attack stages.
- Correlation of the three vulnerability scenarios into a single attack graph.

### Objective

Understand the adversary's hypothesized attack path before reviewing the generated telemetry and detection opportunities.

---

## Phase 2 – Multi-Vector Attack Simulation

The lab used Atomic Operator and AdaptixC2 simulation outputs to model a sequential attack lifecycle.

### Activities

- Sequential atomic-test execution.
- Simulation of multiple attack stages.
- Generation of security events.
- Review of the simulated command-and-control lifecycle.
- Correlation of the stages into a campaign.

The lab output reported successful test execution and generated telemetry for subsequent SIEM investigation.

---

## Phase 3 – SIEM Telemetry & Detection

Wazuh and Elastic Stack were used to review and correlate the simulation's security telemetry.

### Activities

- Review of SIEM cluster health.
- Querying campaign-related logs.
- Correlating events across multiple hosts.
- IOC-based investigation.
- Detection-rule creation and deployment output review.

### Detection Scenarios

The lab displayed three campaign-specific Sigma-style detection rules:

| Detection | Scenario |
|---|---|
| Rule 1 | Edge gateway exploitation indicators |
| Rule 2 | Authentication/token-validation anomalies |
| Rule 3 | Suspicious update-agent process execution |

The simulation reported three detection rules deployed to Wazuh and campaign-associated alerts in the SIEM output.

**Validation caveat:** The displayed deployment and alert results are lab outputs. Independent production validation would require reviewing the actual rule definitions, field mappings, log sources, alert records and test results.

---

## Phase 4 – Incident Management & IOC Enrichment

TheHive and Cortex were used to simulate incident management and threat-intelligence enrichment.

### Activities

- Creation of a Critical-severity incident case.
- Case tagging and task creation.
- IOC submission and enrichment.
- Timeline documentation.
- Observable attachment.
- Review of enrichment results.

### Incident Case

| Field | Value |
|---|---|
| Case | `APT-China-Nexus-Day7` |
| Case ID | `#CASE-2026-007` (lab output) |
| Severity | Critical |
| TLP | Amber (lab output) |
| Case Management | TheHive |
| IOC Enrichment | Cortex |

The lab displayed enrichment results for multiple observables and reported that the observables were associated with the simulated campaign.

IOC verdicts and attribution require independent verification before operational blocking or attribution decisions.

---

## Phase 5 – MITRE ATT&CK Mapping & Reporting

The final phase focused on mapping the simulated activity to MITRE ATT&CK and preparing the investigation evidence.

### Activities

- ATT&CK technique mapping.
- Navigator layer export.
- Incident report generation.
- Markdown report creation.
- Evidence archive creation.
- SHA-256 hash recording.
- Submission output review.

The lab output reported:

- 11 highlighted ATT&CK techniques.
- Coverage across multiple adversary tactics.
- Exported ATT&CK Navigator layer.
- HTML and Markdown incident reports.
- Evidence archive and hash output.

### ATT&CK Coverage

The lab displayed techniques associated with:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Lateral Movement
- Command and Control
- Exfiltration
- Impact

Technique mappings represent the simulation's interpretation and should be validated against actual observed behavior and telemetry.

---

## Defensive Detection PoC

A separate Python script was developed to demonstrate defensive detection logic using synthetic events.

### Detection Scenarios

- Public-facing application anomalies.
- Authentication/token-validation anomalies.
- Unexpected child processes from update components.
- Credential-access signals.
- Lateral-movement signals.
- Outbound beaconing anomalies.

### Run the PoC

```bash
python3 Day7_APT_Defensive_Detection_PoC.py
```

Save the findings:

```bash
python3 Day7_APT_Defensive_Detection_PoC.py --output findings.json
```

The script is an offline demonstration using synthetic data. It does not connect to real infrastructure, execute an attack or modify a system.

---

## Key Learning Outcomes

- Understanding how multiple attack stages can be correlated into a campaign.
- Threat-intelligence analysis and contextual enrichment.
- Understanding the relationship between vulnerability exploitation and subsequent adversary activity.
- SIEM log correlation and investigation.
- Detection engineering fundamentals.
- IOC pivoting and enrichment.
- Incident management using TheHive.
- Threat intelligence workflows using Cortex.
- MITRE ATT&CK mapping.
- Evidence preservation and incident reporting.
- Executive-level communication of cybersecurity risks.

---

## Recommendations Derived from the Scenario

- Validate and remediate verified vulnerabilities using authoritative vendor guidance.
- Review public-facing infrastructure and reduce unnecessary exposure.
- Strengthen authentication, token-validation and privileged-access controls.
- Monitor suspicious process relationships and endpoint activity.
- Review lateral-movement telemetry and privileged account usage.
- Implement network segmentation and outbound traffic monitoring.
- Validate SIEM detection logic against actual log sources.
- Conduct repeatable purple-team exercises.
- Maintain incident timelines, evidence integrity and response documentation.

---

## Project Deliverables

- Executive & CISO Report.
- Detailed Technical PoC with screenshots.
- Python Defensive Detection PoC.
- Lab evidence and investigation walkthrough.

---

## Disclaimer

This project was performed as a controlled cybersecurity lab and educational simulation.

The threat actor profile, vulnerability chain, attack outputs, telemetry, IOC enrichment, detection results and incident artifacts displayed in the lab are scenario-generated and are not independently verified claims of real-world compromise, attribution, vulnerability exploitation or production deployment.

The project is intended for cybersecurity learning, defensive detection engineering, SOC investigation practice and portfolio demonstration.

**Author:** GraySentinel  
**Project:** Week 1 – Day 7 APT Capstone  
**Focus:** Threat Intelligence | Purple Team | Detection Engineering | Incident Response | MITRE ATT&CK
