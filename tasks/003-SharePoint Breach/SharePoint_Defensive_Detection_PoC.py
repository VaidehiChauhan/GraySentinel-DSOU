#!/usr/bin/env python3
"""
SharePoint Defensive Detection PoC
----------------------------------
A SAFE, offline demonstration using synthetic security events only.

What it demonstrates:
  1. Password spraying followed by a successful sign-in
  2. Suspicious OAuth application registration
  3. Unusual access to sensitive SharePoint/HR files
  4. Possible XSS probing
  5. Audit-log tampering attempts

This script:
  - Does NOT connect to SharePoint, Microsoft 365, Entra ID, or any network.
  - Does NOT use credentials, tokens, exploit payloads, or real employee data.
  - Does NOT change files, accounts, permissions, or audit settings.
  - Reads only the synthetic events below, or an optional local JSON file.

Run:
    python3 SharePoint_Defensive_Detection_PoC.py

Optional:
    python3 SharePoint_Defensive_Detection_PoC.py --input my_events.json

Expected JSON input:
    A JSON array of event objects. See SAMPLE_EVENTS below for field names.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


# Synthetic data only. These are fictional identities, IP addresses and filenames.
SAMPLE_EVENTS: list[dict[str, Any]] = [
    # Password spray pattern: several failures across accounts, then a success.
    {"time": "2026-11-21T09:00:00", "type": "signin_failure", "user": "alex@example.test", "src_ip": "198.51.100.25"},
    {"time": "2026-11-21T09:00:20", "type": "signin_failure", "user": "sam@example.test", "src_ip": "198.51.100.25"},
    {"time": "2026-11-21T09:00:40", "type": "signin_failure", "user": "jordan@example.test", "src_ip": "198.51.100.25"},
    {"time": "2026-11-21T09:01:00", "type": "signin_success", "user": "alex@example.test", "src_ip": "198.51.100.25"},

    # Suspicious OAuth application: broad permission and an untrusted-looking redirect.
    {"time": "2026-11-21T09:05:00", "type": "oauth_app_created", "user": "alex@example.test",
     "app_name": "Unapproved-Integration", "permissions": ["Sites.FullControl.All", "Files.ReadWrite.All"],
     "redirect_uri": "https://external-example.test/callback", "admin_consent": True},

    # Multiple sensitive HR document accesses by one identity in a short period.
    {"time": "2026-11-21T09:10:00", "type": "sharepoint_file_access", "user": "alex@example.test",
     "site": "HR", "file": "Synthetic_Employee_Record_A.docx", "sensitivity": "Confidential"},
    {"time": "2026-11-21T09:10:15", "type": "sharepoint_file_access", "user": "alex@example.test",
     "site": "HR", "file": "Synthetic_Payroll_Sample.xlsx", "sensitivity": "Confidential"},
    {"time": "2026-11-21T09:10:30", "type": "sharepoint_file_access", "user": "alex@example.test",
     "site": "HR", "file": "Synthetic_Contract_Sample.pdf", "sensitivity": "Confidential"},

    # Web request containing a script-like marker. This is a logged indicator, not proof of XSS.
    {"time": "2026-11-21T09:15:00", "type": "web_request", "user": "anonymous",
     "path": "/_api/web/lists/items", "parameter": "filter", "input_marker": "<script-like-test-marker>"},

    # Audit tampering attempt.
    {"time": "2026-11-21T09:20:00", "type": "audit_action", "user": "alex@example.test",
     "action": "audit_log_clear_attempt", "result": "blocked"},

    # Benign event to demonstrate that not every event triggers an alert.
    {"time": "2026-11-21T09:25:00", "type": "sharepoint_file_access", "user": "casey@example.test",
     "site": "General", "file": "Team_Readme.txt", "sensitivity": "Public"},
]


def parse_time(value: str) -> datetime:
    """Parse ISO-style timestamps used by the demo."""
    return datetime.fromisoformat(value)


def finding(severity: str, rule: str, title: str, evidence: str, recommendation: str) -> dict[str, str]:
    return {
        "severity": severity,
        "rule": rule,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def detect_password_spray(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    successes = [e for e in events if e.get("type") == "signin_success"]

    for event in events:
        if event.get("type") == "signin_failure":
            failures_by_ip[event.get("src_ip", "unknown")].append(event)

    alerts = []
    for ip, failures in failures_by_ip.items():
        distinct_users = {e.get("user") for e in failures}
        for success in successes:
            if success.get("src_ip") != ip:
                continue
            success_time = parse_time(success["time"])
            recent_failures = [
                e for e in failures
                if timedelta(0) <= success_time - parse_time(e["time"]) <= timedelta(minutes=10)
            ]
            recent_users = {e.get("user") for e in recent_failures}
            if len(recent_users) >= 3:
                alerts.append(finding(
                    "HIGH", "DET-01", "Possible password spray followed by sign-in",
                    f"{len(recent_failures)} failed sign-ins across {len(recent_users)} accounts from {ip}, "
                    f"followed by a successful sign-in for {success.get('user')}.",
                    "Review identity-provider sign-in logs, MFA and conditional-access results. "
                    "Validate the account and source before containment."
                ))
                break
    return alerts


def detect_oauth_risk(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    alerts = []
    risky_terms = ("FullControl", "ReadWrite", "Directory")
    for e in events:
        if e.get("type") != "oauth_app_created":
            continue
        permissions = e.get("permissions", [])
        broad_permissions = [perm for perm in permissions if any(term in perm for term in risky_terms)]
        redirect = e.get("redirect_uri", "")
        external_redirect = "external-example.test" in redirect
        consent = bool(e.get("admin_consent"))
        if broad_permissions or external_redirect or consent:
            alerts.append(finding(
                "HIGH", "DET-02", "Review potentially risky OAuth application registration",
                f"App '{e.get('app_name', 'unknown')}' created by {e.get('user', 'unknown')}; "
                f"broad permissions={broad_permissions or 'none detected'}; "
                f"redirect URI={redirect or 'not supplied'}; admin consent={consent}.",
                "Verify the app owner and business purpose. Review permissions, redirect URI, "
                "credentials and consent audit trail; remove unauthorized grants through approved procedures."
            ))
    return alerts


def detect_sensitive_file_burst(events: list[dict[str, Any]], threshold: int = 3) -> list[dict[str, str]]:
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("type") == "sharepoint_file_access" and (
            e.get("site", "").lower() == "hr" or e.get("sensitivity", "").lower() in {"confidential", "restricted"}
        ):
            by_user[e.get("user", "unknown")].append(e)

    alerts = []
    for user, user_events in by_user.items():
        if len(user_events) >= threshold:
            filenames = sorted({e.get("file", "unknown") for e in user_events})
            alerts.append(finding(
                "MEDIUM", "DET-03", "Unusual access volume to sensitive SharePoint files",
                f"{user} accessed {len(user_events)} sensitive-file records in the supplied event set: "
                f"{', '.join(filenames)}.",
                "Check whether the user is authorized, compare with their normal activity, and review "
                "download, sharing, device and network telemetry."
            ))
    return alerts


def detect_xss_probe(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    alerts = []
    indicators = ("<script", "onload", "javascript:", "<svg")
    for e in events:
        if e.get("type") != "web_request":
            continue
        marker = str(e.get("input_marker", "")).lower()
        if any(indicator in marker for indicator in indicators):
            alerts.append(finding(
                "MEDIUM", "DET-04", "Possible XSS probing in web request",
                f"Request to {e.get('path', 'unknown path')} included a script-like input marker "
                f"in parameter '{e.get('parameter', 'unknown')}'.",
                "Correlate with WAF/server logs and safely validate output encoding in a test environment. "
                "A probe alone does not prove script execution or exploitable XSS."
            ))
    return alerts


def detect_audit_tampering(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    alerts = []
    for e in events:
        if e.get("type") == "audit_action" and "audit_log" in str(e.get("action", "")).lower():
            alerts.append(finding(
                "CRITICAL", "DET-05", "Audit-log tampering action detected",
                f"User {e.get('user', 'unknown')} generated action '{e.get('action')}' "
                f"with result '{e.get('result', 'unknown')}'.",
                "Preserve centralized immutable copies, investigate the actor and authorization, "
                "and check for ingestion gaps. Treat blocked attempts as security events too."
            ))
    return alerts


def run_detections(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Run all detection rules against the supplied event list."""
    results: list[dict[str, str]] = []
    results.extend(detect_password_spray(events))
    results.extend(detect_oauth_risk(events))
    results.extend(detect_sensitive_file_burst(events))
    results.extend(detect_xss_probe(events))
    results.extend(detect_audit_tampering(events))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline SharePoint defensive detection PoC (synthetic data).")
    parser.add_argument("--input", help="Optional local JSON file containing an array of synthetic/log event objects.")
    parser.add_argument("--output", help="Optional path to save findings as JSON.")
    args = parser.parse_args()

    if args.input:
        input_path = Path(args.input)
        with input_path.open("r", encoding="utf-8") as handle:
            events = json.load(handle)
        if not isinstance(events, list):
            raise SystemExit("Input JSON must be an array of event objects.")
        source = str(input_path)
    else:
        events = SAMPLE_EVENTS
        source = "built-in synthetic sample events"

    results = run_detections(events)

    print("=" * 72)
    print(" SHAREPOINT DEFENSIVE DETECTION PoC")
    print("=" * 72)
    print(f"Input source : {source}")
    print(f"Events read  : {len(events)}")
    print(f"Alerts raised: {len(results)}")
    print()

    if not results:
        print("No detections triggered for the supplied events.")
    else:
        for index, alert in enumerate(results, start=1):
            print(f"[{index}] [{alert['severity']}] {alert['rule']} — {alert['title']}")
            print(f"    Evidence       : {alert['evidence']}")
            print(f"    Recommendation : {alert['recommendation']}")
            print()

    if args.output:
        with Path(args.output).open("w", encoding="utf-8") as handle:
            json.dump({"event_count": len(events), "alert_count": len(results), "findings": results},
                      handle, indent=2)
        print(f"Findings saved to: {args.output}")

    print("\nNote: This is an educational detection demonstration, not a production SIEM rule pack.")
    print("Validate detections against real, authorized telemetry before operational use.")


if __name__ == "__main__":
    main()
