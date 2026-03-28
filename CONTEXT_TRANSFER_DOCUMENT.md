# CONTEXT TRANSFER DOCUMENT — MORPH
# Last Updated: 2026-03-28

---

## 1. CORE IDENTITY

- **Project:** MORPH (Modular Reactive Polymorphic Honeypot)
- **Type:** Solo side project
- **Stack:** Python + Flask + HTMX
- **Goal:** Adaptive honeypot that models attacker behavior, prolongs interaction, and generates intelligence dossiers

---

## 2. CORE PROBLEM

Traditional honeypots are static and easily detectable, limiting their ability to capture meaningful attacker behavior and produce actionable threat intelligence.

---

## 3. SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                         MORPH                               │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│ log_parser  │ classifier  │  dossier    │     app.py       │
│   .py       │    .py      │    .py      │   (Flask UI)     │
├─────────────┴─────────────┴─────────────┴──────────────────┤
│ deception.py │ adaptor.py │   reactor.py  │    sync.py     │
├────────────────────────────────────────────────────────────┤
│                    main.py (orchestrator)                   │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Cowrie Honeypot                        │
│  - cowrie.json logs                                         │
│  - honeyfs/ (fake filesystem)                               │
│  - fs.pickle (filesystem metadata)                          │
└─────────────────────────────────────────────────────────────┘
```

**Primary metric:** attacker dwell time
**Differentiator:** adaptive behavior based on attacker actions

---

## 4. COMPONENTS — STATUS

| File | Purpose | Status |
|------|---------|--------|
| `main.py` | Entry point - runs pipeline then starts Flask | ✅ |
| `log_parser.py` | Parses cowrie.json, aggregates by session | ✅ |
| `classifier.py` | Rule-based classification (bot/human, intent, risk) | ✅ |
| `dossier.py` | Generates JSON dossiers in morph/dossiers/ | ✅ |
| `deception.py` | Creates static fake assets (SQL dumps, API keys, .env) | ✅ |
| `adaptor.py` | Learns from history, adapts environment per-session | ✅ |
| `reactor_wsl.py` | Real-time file watcher, plants files in honeyfs | ✅ |
| `reactor.py` | Windows-side reaction logic (not used standalone) | ✅ |
| `sync.py` | Copies cowrie.json from WSL to Windows | ✅ |
| `app.py` | Flask web UI with HTMX | ✅ |
| `templates/` | Jinja2 templates (base, index, sessions, dossier, live_logs) | ✅ |

---

## 5. KEY PATHS

### Current (Windows+WSL) - NEEDS UPDATE FOR LINUX
```
Cowrie installation:    /home/cowrie/cowrie/
Cowrie logs:            /home/cowrie/cowrie/var/log/cowrie/cowrie.json
Cowrie honeyfs:         /home/cowrie/cowrie/honeyfs/
Cowrie fs.pickle:       /home/cowrie/cowrie/src/cowrie/data/fs.pickle
Cowrie PID file:        /home/cowrie/cowrie/twistd.pid
Cowrie venv python:     /home/cowrie/cowrie/cowrie-env/bin/python3
fsctl tool:             /home/cowrie/cowrie/cowrie-env/bin/fsctl

MORPH logs:             morph/reactor.log, morph/adaptor.log, morph/sync.log, morph/deception.log
MORPH dossiers:         morph/dossiers/<session_id>.json
```

---

## 6. CLASSIFICATION RULES

**Type (bot vs human):**
- Bot: rapid commands (>2/sec), repeated logins (>5), scanner patterns, known sequences
- Human: slow interaction, varied commands, exploratory cd/ls

**Intent:**
- Recon: whoami, uname, ls, cat /etc/passwd, ifconfig
- Exploit: wget, curl, chmod +x, ./payload, python -c
- Persistence: crontab, .bashrc, adduser, authorized_keys

**Risk:**
- Low: only recon, no downloads
- Medium: exploit attempts, no execution
- High: downloads + execution, or persistence

---

## 7. REACTOR TRIGGERS

| Attacker Command | Files Created in honeyfs |
|-----------------|--------------------------|
| `ls/cd /var/www` | `var/www/html/config.php`, `.git/config` |
| `ps aux`, `top` | `tmp/.monitor` |
| `cat /etc/passwd` | `home/deploy/.ssh/authorized_keys`, `.bash_history` |
| `find`, `locate` | `opt/backup/db_backup_2024.sql.gz`, `opt/scripts/backup.sh` |
| `wget`, `curl` | `tmp/<random>.sh` (fake prior malware) |

After creating files, reactor:
1. Runs fsctl to register in fs.pickle
2. Sends SIGHUP to Cowrie to reload

---

## 8. ADAPTOR RULES

| Condition | Adaptation |
|-----------|------------|
| Backup path targeted | Move to random path like `/opt/.cache/abc123/` |
| 2+ shadow attempts | Replace with crackable md5crypt hashes |
| Bot detected | Add extended /etc/services (50+ fake ports) |
| Human + exploit | Plant fake WIP exploit in /tmp/work/ |

---

## 9. DOSSIER STRUCTURE

```json
{
  "session_id": "abc123",
  "src_ip": "192.168.1.100",
  "start_time": "2024-03-15T10:30:00",
  "end_time": "2024-03-15T10:35:45",
  "duration_seconds": 345,
  "login_attempts": [{"username": "root", "password": "admin", "success": false}],
  "commands": ["whoami", "uname -a"],
  "downloads": ["http://evil.com/bot"],
  "classification": {
    "type": "bot",
    "intent": "exploit",
    "risk": "high",
    "matched_rules": ["rapid_commands", "downloads:1"]
  },
  "environment_adaptations": {...},
  "generated_at": "2024-03-15T14:22:33Z"
}
```

---

## 10. WEB UI ROUTES

| Route | Description |
|-------|-------------|
| `GET /` | Dashboard with stats |
| `GET /sessions` | Session list with badges |
| `GET /dossier/<id>` | Full dossier view |
| `GET /live-logs` | Auto-refresh log tail (HTMX every 3s) |
| `GET /api/logs` | HTMX endpoint for log fragment |

---

## 11. RUNNING ON LINUX

```bash
# Install dependencies
pip install flask watchdog

# Terminal 1: Reactor (real-time deception)
python3 reactor.py

# Terminal 2: Main pipeline + Flask
python3 main.py
# Dashboard at http://localhost:5000
```

**Pipeline steps:**
1. Parse cowrie.json → sessions dict
2. Classify each session
3. Generate dossiers
4. Run per-session deception
5. Run environment adaptation from history
6. Start Flask UI

---

## 12. MIGRATION CHECKLIST FOR LINUX

1. **Delete sync.py dependency** - no longer needed on same filesystem
2. **Update log_parser.py** - change `COWRIE_LOG`:
   ```python
   COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
   ```
3. **Update adaptor.py** - change `HONEYFS_ROOT`:
   ```python
   HONEYFS_ROOT = "/home/cowrie/cowrie/honeyfs"
   ```
4. **Rename reactor_wsl.py → reactor.py** - it's now your main reactor
5. **Update main.py** - remove sync imports and calls:
   - Remove: `from sync import sync_log_safe, watch_and_sync, stop_sync`
   - Remove: `sync_log_safe()` call
   - Remove: `watch_and_sync(interval=30)` call
   - Remove: `stop_sync()` call

---

## 13. DEPENDENCIES

```
flask
watchdog
```

---

## 14. CURRENT STATE

All modules implemented and tested on Windows+WSL. Ready to consolidate on native Linux.
