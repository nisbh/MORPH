#!/usr/bin/env python3
"""
MORPH - Session Memory and Adaptation Layer

Learns from previous attack sessions and adapts the honeypot environment
to increase dwell time and prevent fingerprinting across connections.
"""

import random
import string
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from dossier import load_all

# Paths
HONEYFS_ROOT = "/home/nb/cowrie/honeyfs"
DOSSIERS_PATH = "/home/nb/GitHub Projects/MORPH/dossiers/"
ADAPTOR_LOG = "morph/adaptor.log"

# Track adaptations made in current run
_current_adaptations: list[dict[str, Any]] = []


def _log(message: str) -> None:
    """Log an adaptor action."""
    log_path = Path(ADAPTOR_LOG)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry)


def _random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _write_honeyfs_file(relative_path: str, content: str) -> bool:
    """Write a file into the honeyfs directory."""
    full_path = Path(HONEYFS_ROOT) / relative_path
    
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        _log(f"Written: {relative_path}")
        return True
    except IOError as e:
        _log(f"Error writing {relative_path}: {e}")
        return False


def load_history() -> dict[str, Any]:
    """
    Load and analyze all previous dossiers to build an attacker profile.
    
    Returns:
        Dict with:
        - total_sessions: int
        - risk_distribution: {low: n, medium: n, high: n}
        - type_distribution: {bot: n, human: n}
        - common_commands: [(cmd, count), ...]
        - targeted_paths: [(path, count), ...]
        - high_risk_count: int
        - shadow_attempts: int
        - backup_attempts: int
    """
    dossiers = load_all()
    
    history = {
        "total_sessions": len(dossiers),
        "risk_distribution": {"low": 0, "medium": 0, "high": 0},
        "type_distribution": {"bot": 0, "human": 0},
        "intent_distribution": {"recon": 0, "exploit": 0, "persistence": 0},
        "common_commands": [],
        "targeted_paths": [],
        "high_risk_count": 0,
        "shadow_attempts": 0,
        "backup_attempts": 0,
        "download_attempts": 0,
    }
    
    if not dossiers:
        _log("No historical dossiers found")
        return history
    
    all_commands: list[str] = []
    path_mentions: list[str] = []
    
    for dossier in dossiers:
        classification = dossier.get("classification", {})
        
        # Count risk levels
        risk = classification.get("risk", "low")
        if risk in history["risk_distribution"]:
            history["risk_distribution"][risk] += 1
        if risk == "high":
            history["high_risk_count"] += 1
        
        # Count types
        session_type = classification.get("type", "bot")
        if session_type in history["type_distribution"]:
            history["type_distribution"][session_type] += 1
        
        # Count intents
        intent = classification.get("intent", "recon")
        if intent in history["intent_distribution"]:
            history["intent_distribution"][intent] += 1
        
        # Collect commands
        commands = dossier.get("commands", [])
        all_commands.extend(commands)
        
        # Check for specific patterns
        for cmd in commands:
            cmd_lower = cmd.lower()
            
            # Track shadow file attempts
            if "/etc/shadow" in cmd_lower or "/etc/passwd" in cmd_lower:
                history["shadow_attempts"] += 1
            
            # Track backup path attempts
            if "/opt/backup" in cmd_lower or "backup" in cmd_lower:
                history["backup_attempts"] += 1
                path_mentions.append("/opt/backup")
            
            # Track downloads
            if "wget " in cmd_lower or "curl " in cmd_lower:
                history["download_attempts"] += 1
            
            # Extract paths from commands
            for token in cmd.split():
                if token.startswith("/"):
                    path_mentions.append(token)
    
    # Count most common commands
    cmd_counts = Counter(all_commands)
    history["common_commands"] = cmd_counts.most_common(20)
    
    # Count most targeted paths
    path_counts = Counter(path_mentions)
    history["targeted_paths"] = path_counts.most_common(20)
    
    _log(f"Loaded history: {history['total_sessions']} sessions, "
         f"{history['high_risk_count']} high-risk, "
         f"{history['shadow_attempts']} shadow attempts")
    
    return history


# === Fake Content for Adaptations ===

FAKE_SHADOW_CRACKABLE = """root:$1$xyz$7zT3k2pQ9vL1mN5rK4hJ6.:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
sys:*:19000:0:99999:7:::
sync:*:19000:0:99999:7:::
games:*:19000:0:99999:7:::
man:*:19000:0:99999:7:::
lp:*:19000:0:99999:7:::
mail:*:19000:0:99999:7:::
news:*:19000:0:99999:7:::
uucp:*:19000:0:99999:7:::
proxy:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
backup:$1$abc$L8kP2mN4rT6vX9yJ3hG5.:19000:0:99999:7:::
deploy:$1$def$K7jM1nQ3sU5wY8zL2fH4.:19000:0:99999:7:::
admin:$1$ghi$N9pR4tV6xA2cE5gI1jK3.:19000:0:99999:7:::
svc_backup:$1$jkl$P1sT3uW5yB4dF6hJ2kL8.:19000:0:99999:7:::
"""

FAKE_SERVICES_EXTENDED = """# /etc/services - Extended service list
tcpmux		1/tcp
echo		7/tcp
echo		7/udp
discard		9/tcp		sink null
discard		9/udp		sink null
systat		11/tcp		users
daytime		13/tcp
daytime		13/udp
netstat		15/tcp
qotd		17/tcp		quote
chargen		19/tcp		ttytst source
chargen		19/udp		ttytst source
ftp-data	20/tcp
ftp		21/tcp
ssh		22/tcp
telnet		23/tcp
smtp		25/tcp		mail
time		37/tcp		timserver
time		37/udp		timserver
whois		43/tcp		nicname
domain		53/tcp
domain		53/udp
bootps		67/udp
bootpc		68/udp
tftp		69/udp
gopher		70/tcp
finger		79/tcp
http		80/tcp		www
kerberos	88/tcp		kerberos-sec
kerberos	88/udp		kerberos-sec
pop3		110/tcp		pop-3
sunrpc		111/tcp		portmapper
sunrpc		111/udp		portmapper
auth		113/tcp		ident
nntp		119/tcp		usenet
ntp		123/udp
netbios-ns	137/udp
netbios-dgm	138/udp
netbios-ssn	139/tcp
imap		143/tcp		imap2
snmp		161/udp
snmp-trap	162/udp
ldap		389/tcp
https		443/tcp
smb		445/tcp		microsoft-ds
kpasswd		464/tcp
kpasswd		464/udp
submissions	465/tcp		smtps
syslog		514/udp
printer		515/tcp		spooler
talk		517/udp
ntalk		518/udp
route		520/udp		router routed
nntps		563/tcp		snntp
ldaps		636/tcp
imaps		993/tcp
pop3s		995/tcp
mysql		3306/tcp
mysql-proxy	3307/tcp
rdp		3389/tcp	ms-wbt-server
postgresql	5432/tcp	postgres
vnc		5900/tcp
vnc-1		5901/tcp
vnc-2		5902/tcp
redis		6379/tcp
http-alt	8080/tcp	http-proxy
https-alt	8443/tcp
mongodb		27017/tcp
memcached	11211/tcp
elasticsearch	9200/tcp
kibana		5601/tcp
grafana		3000/tcp
jenkins		8081/tcp
docker		2375/tcp
docker-ssl	2376/tcp
kubernetes	6443/tcp
etcd		2379/tcp
consul		8500/tcp
vault		8200/tcp
nomad		4646/tcp
"""

FAKE_EXPLOIT_SCRIPT = """#!/usr/bin/env python3
# WIP - don't run yet, still testing
# target: {target}
# author: xXhax0rXx
# date: {date}

import socket
import struct
import sys

TARGET = "{ip}"
PORT = 22

# shellcode placeholder - need to generate for target arch
SHELLCODE = b"\\x90" * 100  # NOP sled

def exploit():
    '''
    TODO: 
    - finish ROP chain
    - test on staging first
    - add cleanup routine
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET, PORT))
    
    # buffer overflow payload
    payload = b"A" * 256
    payload += struct.pack("<Q", 0x{addr1})  # pop rdi; ret
    payload += struct.pack("<Q", 0x{addr2})  # /bin/sh address
    payload += struct.pack("<Q", 0x{addr3})  # system@plt
    
    # NOT WORKING YET - segfaults
    # s.send(payload)
    
    print("[*] Payload sent... check listener")

if __name__ == "__main__":
    print("[!] INCOMPLETE - DO NOT RUN")
    # exploit()
"""


def adapt_environment(current_classification: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """
    Adapt the honeypot environment based on historical patterns.
    
    Args:
        current_classification: Optional classification of current session
        
    Returns:
        List of adaptation actions taken
    """
    global _current_adaptations
    _current_adaptations = []
    
    history = load_history()
    
    if history["total_sessions"] == 0:
        _log("No history available, applying default adaptations")
        _apply_default_adaptations()
        return _current_adaptations
    
    _log(f"Adapting environment based on {history['total_sessions']} historical sessions")
    
    # Rule 1: If previous high-risk sessions found /opt/backup → relocate
    if history["backup_attempts"] >= 1:
        _adapt_backup_location(history)
    
    # Rule 2: If 2+ sessions tried /etc/shadow → add crackable shadow
    if history["shadow_attempts"] >= 2:
        _adapt_shadow_file(history)
    
    # Rule 3: If previous bot detected → add more fake services
    if history["type_distribution"]["bot"] >= 1:
        _adapt_services_file(history)
    
    # Rule 4: If previous human+exploit → add fake exploit script
    exploit_humans = 0
    for dossier in load_all():
        classification = dossier.get("classification", {})
        if classification.get("type") == "human" and classification.get("intent") == "exploit":
            exploit_humans += 1
    
    if exploit_humans >= 1:
        _adapt_exploit_script(history)
    
    _log(f"Applied {len(_current_adaptations)} adaptations")
    return _current_adaptations


def _apply_default_adaptations() -> None:
    """Apply default adaptations when no history exists."""
    _record_adaptation(
        "default_setup",
        "No historical data, environment unchanged",
        []
    )


def _adapt_backup_location(history: dict) -> None:
    """Move fake backup to randomized location."""
    random_path = f"opt/.cache/{_random_string(6)}/data"
    backup_file = f"{random_path}/db_backup_2024.sql.gz"
    
    _write_honeyfs_file(backup_file, "")  # Empty file, believable name
    
    # Also add a breadcrumb in the old location
    breadcrumb = f"opt/backup/.moved"
    _write_honeyfs_file(breadcrumb, f"# Moved to /{random_path}/ per security policy\n")
    
    _record_adaptation(
        "relocate_backup",
        f"Backup path targeted {history['backup_attempts']} times, relocated to /{random_path}/",
        [f"/{backup_file}", f"/{breadcrumb}"]
    )


def _adapt_shadow_file(history: dict) -> None:
    """Replace shadow file with crackable hashes."""
    _write_honeyfs_file("etc/shadow", FAKE_SHADOW_CRACKABLE)
    
    _record_adaptation(
        "crackable_shadow",
        f"Shadow file targeted {history['shadow_attempts']} times, replaced with crackable md5crypt hashes",
        ["/etc/shadow"]
    )


def _adapt_services_file(history: dict) -> None:
    """Add extended services file to waste scanner time."""
    _write_honeyfs_file("etc/services", FAKE_SERVICES_EXTENDED)
    
    _record_adaptation(
        "extended_services",
        f"Bot activity detected ({history['type_distribution']['bot']} sessions), added extended services list",
        ["/etc/services"]
    )


def _adapt_exploit_script(history: dict) -> None:
    """Add fake partially-written exploit script."""
    fake_script = FAKE_EXPLOIT_SCRIPT.format(
        target="internal-app.corp",
        date=datetime.now().strftime("%Y-%m-%d"),
        ip="10.0.0." + str(random.randint(1, 254)),
        addr1=_random_string(6),
        addr2=_random_string(6),
        addr3=_random_string(6),
    )
    
    _write_honeyfs_file("tmp/work/exploit_wip.py", fake_script)
    _write_honeyfs_file("tmp/work/.notes", "SSH vuln on internal boxes - need more recon\nCheck back after 2am maintenance window\n")
    
    _record_adaptation(
        "fake_exploit",
        "Human exploit activity detected, planted fake WIP exploit to increase curiosity",
        ["/tmp/work/exploit_wip.py", "/tmp/work/.notes"]
    )


def _record_adaptation(rule_name: str, reason: str, files_created: list[str]) -> None:
    """Record an adaptation action."""
    adaptation = {
        "rule": rule_name,
        "reason": reason,
        "files_created": files_created,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    _current_adaptations.append(adaptation)
    _log(f"Adaptation [{rule_name}]: {reason}")


def generate_adaptation_report() -> dict[str, Any]:
    """
    Generate a report of all adaptations made.
    
    Returns:
        Dict with adaptation details for inclusion in dossiers
    """
    return {
        "adaptations_applied": len(_current_adaptations),
        "details": _current_adaptations,
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }


if __name__ == "__main__":
    print("MORPH Adaptor - Session Memory and Adaptation Layer")
    print("=" * 60)
    
    # Load and display history
    print("\nLoading attack history...")
    history = load_history()
    
    print(f"\nHistory Summary:")
    print(f"  Total sessions: {history['total_sessions']}")
    print(f"  Risk distribution: {history['risk_distribution']}")
    print(f"  Type distribution: {history['type_distribution']}")
    print(f"  Shadow attempts: {history['shadow_attempts']}")
    print(f"  Backup attempts: {history['backup_attempts']}")
    
    if history["common_commands"]:
        print(f"\n  Top commands:")
        for cmd, count in history["common_commands"][:5]:
            print(f"    {count}x: {cmd[:50]}")
    
    # Apply adaptations
    print("\n" + "-" * 60)
    print("Applying adaptations...")
    adaptations = adapt_environment()
    
    print(f"\nAdaptations applied: {len(adaptations)}")
    for a in adaptations:
        print(f"  [{a['rule']}] {a['reason']}")
    
    # Generate report
    print("\n" + "-" * 60)
    report = generate_adaptation_report()
    print(f"Report generated with {report['adaptations_applied']} adaptations")
    print(f"\nLog file: {ADAPTOR_LOG}")
