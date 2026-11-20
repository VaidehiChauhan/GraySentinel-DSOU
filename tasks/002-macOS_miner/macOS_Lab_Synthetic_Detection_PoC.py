#!/usr/bin/env python3
"""
SAFE synthetic detection demonstration for the macOS attack-chain lab.

This program does not exploit CVE-2026-65400, connect to any host, download
software, execute shell commands, create persistence, alter SSH keys, or
install/remove a miner. It evaluates synthetic event records in memory only.
"""
from dataclasses import dataclass

@dataclass
class LabEvent:
    event_id: str
    category: str
    process: str
    detail: str

RULES = {
    "office_child_shell": "Office application spawned a shell or interpreter",
    "launchagent_change": "Unexpected LaunchAgent/LaunchDaemon change",
    "screen_sharing_inbound": "Unexpected inbound Screen Sharing connection",
    "ssh_key_change": "Unexpected authorized_keys modification",
    "remote_agent": "Unapproved remote-control agent indicator",
    "cryptominer": "Cryptominer process or persistence indicator",
}

def evaluate(event: LabEvent):
    reason = RULES.get(event.category)
    return (reason is not None, reason or "No match in this demonstration rule set")

def main():
    events = [
        LabEvent("LAB-001", "office_child_shell", "Microsoft Word",
                 "Synthetic Office-to-shell process relationship"),
        LabEvent("LAB-002", "launchagent_change", "launchd",
                 "Synthetic new LaunchAgent plist"),
        LabEvent("LAB-003", "screen_sharing_inbound", "screensharingd",
                 "Synthetic inbound connection to TCP 5900"),
        LabEvent("LAB-004", "ssh_key_change", "sshd",
                 "Synthetic authorized_keys file modification"),
        LabEvent("LAB-005", "remote_agent", "unknown-agent",
                 "Synthetic unapproved remote-control agent"),
        LabEvent("LAB-006", "cryptominer", "xmrig",
                 "Synthetic miner process / LaunchDaemon indicator"),
        LabEvent("LAB-007", "normal_activity", "Finder",
                 "Synthetic ordinary user activity"),
    ]
    print("MACOS LAB DETECTION DEMO — SYNTHETIC EVENTS ONLY")
    print("-" * 68)
    for event in events:
        matched, reason = evaluate(event)
        status = "FLAG FOR REVIEW" if matched else "NO MATCH"
        print(f"{status:16} {event.event_id} | {event.process}")
        print(f"                 {reason}")
        print(f"                 {event.detail}")
    print("-" * 68)
    print("Finished: no network, files, services, accounts or remote systems changed.")
    print("This demonstrates logic only; it is not a production Wazuh rule.")

if __name__ == "__main__":
    main()
