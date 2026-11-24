# Day 6 – Operation Log Wrangler

**Project:** GraySentinel-DSOU  
**Focus:** Windows PowerShell Script Block Logging & Syslog-ng Log Collection  
**Environment:** Windows + Kali Linux

## 1. Overview

Day 6 focused on configuring centralized log collection using Syslog-ng and enabling PowerShell Script Block Logging on a Windows endpoint.

The objective was to capture PowerShell script execution activity, verify Event ID 4104 in Windows Event Logs, and identify PowerShell-related log entries on the Kali Linux Syslog-ng collector.

## 2. Objectives

- Verify Syslog-ng installation and service status.
- Configure Windows Event Collector.
- Enable PowerShell Script Block Logging.
- Identify Event ID 4104 in Windows Event Logs.
- Verify PowerShell-related logs on Kali Linux.
- Understand Syslog-ng sources, filters, destinations and log paths.
- Validate log collection and troubleshoot the service.

## 3. Lab Environment

| Component | Details |
|---|---|
| Source system | Windows |
| Source IP | `192.168.56.105` |
| Destination system | Kali Linux |
| Log collector | Syslog-ng |
| Listening port | TCP 514 |
| Windows Event Channel | Microsoft-Windows-PowerShell/Operational |
| Event ID | 4104 |
| Configuration file | `/etc/syslog-ng/syslog-ng.conf` |
| Log file | `/var/log/syslog-ng/syslog-ng.log` |

**Note:** `192.168.56.105` was identified as the source IP from the received log entries. The Kali destination IP needs to be verified separately.

## 4. Activities Performed

### Phase 1 – Syslog-ng Version Check

Verified the Syslog-ng installation and version.

```bash
syslog-ng --version
```

**Result:** Syslog-ng version 3.38.1 was detected.

### Phase 2 – Syslog-ng Service Status

Checked whether the Syslog-ng service was running.

```bash
sudo systemctl status syslog-ng
```

**Result:** Service status showed `active (running)`.

### Phase 3 – Configure Windows Event Collector

Executed the Windows Event Collector quick-configuration command.

```powershell
wecutil qc /q
```

**Result:** Windows Event Collector was configured successfully.

### Phase 4 – Verify Log Reception on Kali

Checked the last 20 entries in the Syslog-ng log file.

```bash
sudo tail -20 /var/log/syslog-ng/syslog-ng.log
```

**Result:** Application, Security and System event messages appeared with source IP `192.168.56.105`.

### Phase 5 – Enable PowerShell Script Block Logging

Created the registry key for Script Block Logging.

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
```

**Result:** Registry key was created successfully and `EnableScriptBlockLogging` was displayed as `1`.

### Phase 6 – Test PowerShell Script Block Logging

Queried the PowerShell Operational event log.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents 5
```

**Result:** Event ID 4104 records displayed the executed PowerShell script content.

### Phase 7 – Verify PowerShell Logs on Kali

Searched the Syslog-ng log file for PowerShell-related entries.

```bash
sudo grep -i "powershell" /var/log/syslog-ng/syslog-ng.log
```

**Result:** A PowerShell-related test message was found in the Kali log file.

### Phase 8 – Review Syslog-ng Configuration

Reviewed the configuration file.

```bash
sudo cat /etc/syslog-ng/syslog-ng.conf
```

Reviewed:
- Sources – Where logs enter Syslog-ng.
- Filters – Which logs should be selected.
- Destinations – Where logs should be stored.
- Log paths – How sources, filters and destinations are connected.

### Phase 9 – Start Syslog-ng Service

Started the service manually.

```bash
sudo systemctl start syslog-ng
```

**Result:** Syslog-ng started successfully and showed `active (running)`.

## 5. Key Findings

- Syslog-ng was installed and running on Kali Linux.
- Windows Event Collector quick configuration completed successfully.
- PowerShell Script Block Logging was enabled.
- Event ID 4104 captured PowerShell script content.
- PowerShell-related test messages were found in the Syslog-ng log file.
- The Syslog-ng configuration contained TCP port 514, source definitions, filters and file destinations.

## 6. Security Significance

PowerShell is frequently used by administrators but can also be abused by attackers to execute malicious commands.

Script Block Logging provides visibility into PowerShell script content, helping SOC analysts investigate suspicious activity.

Centralized logging helps security teams collect, preserve and analyze logs from multiple systems.

## 7. Important Validation Gap

The lab screenshots demonstrate local PowerShell event generation and PowerShell-related text in the Kali log.

However, they do not show the complete Windows-to-Kali forwarding mechanism, such as a WEF subscription or forwarding-agent configuration.

Therefore, the actual transport mechanism and end-to-end forwarding path require additional verification before considering this a fully validated production deployment.

## 8. Recommendations

- Verify the actual Windows-to-Kali forwarding mechanism.
- Confirm the Kali collector IP and network connectivity.
- Restrict access to the Syslog-ng listening port.
- Use encrypted and authenticated log transport in production.
- Configure appropriate log retention and access controls.
- Monitor Syslog-ng service availability.
- Integrate collected logs with a SIEM for correlation and alerting.

## 9. Deliverables

| Document | Description |
|---|---|
| Executive & CISO Report | Executive summary, security findings, risks and recommendations |
| Technical PoC | Detailed implementation steps, commands, explanations and screenshots |

## 10. Learning Outcome

Gained practical exposure to Windows PowerShell Script Block Logging, Windows Event ID 4104, Syslog-ng configuration, Linux service management and basic centralized log validation.

**Lab:** GraySentinel-DSOU  
**Day:** 6 – Operation Log Wrangler
