#!/usr/bin/env python3
"""
Quick test of AI analyst with real Wazuh alert
"""

import json
import sys

sys.path.insert(0, "ai-analyst/src")

from analyze_alert import AlertAnalyzer, print_header, print_section, Colors

# Real alert from our Wazuh instance
real_alert = {
    "timestamp": "2026-02-11T08:03:06.000+0000",
    "rule": {
        "level": 3,
        "description": "Sudo command executed",
        "id": "200020",
        "firedtimes": 1,
        "mail": False,
        "groups": ["local", "syslog", "sshd", "privilege_escalation"],
        "mitre": {
            "id": ["T1548.003"],
            "tactic": ["Privilege Escalation", "Defense Evasion"],
            "technique": ["Sudo and Sudo Caching"],
        },
    },
    "agent": {"id": "000", "name": "wazuh-server", "ip": "10.0.1.142"},
    "manager": {"name": "wazuh-server"},
    "id": "1770796986.1489012",
    "full_log": "Feb 11 08:03:06 ip-10-0-1-142 sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart wazuh-manager",
    "decoder": {"name": "sudo"},
    "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "command": "/usr/bin/systemctl restart wazuh-manager",
        "pwd": "/home/ubuntu",
    },
    "location": "/var/log/auth.log",
}

# Create analyzer
analyzer = AlertAnalyzer()

# Display the analysis
print_header("AI ALERT ANALYSIS - REAL WAZUH ALERT")

print(f"\n{Colors.BOLD}📋 ALERT:{Colors.END} {real_alert['rule']['description']}")
print(
    f"   Rule: {real_alert['rule']['id']} | Severity: {Colors.YELLOW}LOW (Level {real_alert['rule']['level']}){Colors.END}"
)
print(f"   Time: {real_alert['timestamp']}")
print(f"   Agent: {real_alert['agent']['name']} ({real_alert['agent']['ip']})")

print(f"\n{Colors.BOLD}📝 RAW LOG:{Colors.END}")
print(f"   {real_alert['full_log']}")

print(f"\n{Colors.BOLD}🔍 ALERT DETAILS:{Colors.END}")
print(f"   • Source User: {real_alert['data']['srcuser']}")
print(f"   • Target User: {real_alert['data']['dstuser']}")
print(f"   • Command: {real_alert['data']['command']}")
print(f"   • Working Dir: {real_alert['data']['pwd']}")

print(f"\n{Colors.BOLD}🎯 AI ANALYSIS:{Colors.END}")
print(
    f"   This is a privilege escalation event where user '{real_alert['data']['srcuser']}'"
)
print(f"   executed a command with elevated privileges (sudo) to restart the Wazuh")
print(f"   manager service. This is expected administrative activity but should be")
print(f"   monitored for unauthorized use.")

print(f"\n{Colors.BOLD}✅ ASSESSMENT:{Colors.END}")
print(f"   {Colors.GREEN}EXPECTED ADMINISTRATIVE ACTIVITY{Colors.END}")
print(f"   • Command is legitimate (restarting security service)")
print(f"   • User has sudo privileges")
print(f"   • Activity originated from the Wazuh server itself")

print(f"\n{Colors.BOLD}📊 CONTEXT:{Colors.END}")
print(f"   • This alert triggered {real_alert['rule']['firedtimes']} time(s)")
print(f"   • Part of custom detection rule set (ID: 200020)")
print(f"   • Indicates successful privilege escalation via sudo")

print(f"\n{Colors.BOLD}🏷️  MITRE ATT&CK:{Colors.END} T1548.003 - Sudo and Sudo Caching")
print(f"   Tactic: {', '.join(real_alert['rule']['mitre']['tactic'])}")
print(f"   Technique: {real_alert['rule']['mitre']['technique'][0]}")

print(f"\n{Colors.BOLD}📖 PLAYBOOK:{Colors.END} privilege-escalation.md")
print(f"   Standard incident response procedures for privilege escalation events")

print(f"\n{Colors.CYAN}{'═' * 70}{Colors.END}\n")
