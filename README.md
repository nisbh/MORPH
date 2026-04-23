# MORPH — Modular Reactive Polymorphic Honeypot

An adaptive SSH honeypot system built on Cowrie that increases attacker dwell time, classifies behavior in real-time, and generates structured intelligence dossiers.

> **Live deployment:** Actively capturing real-world attack data on a public VPS since March 2026.

---

## What It Does

Traditional honeypots are static and easily fingerprinted. Attackers recognize them and leave quickly. MORPH solves this by making the environment react and evolve:

1. **Watches attackers in real-time** — tails Cowrie logs as they're written
2. **Plants bait mid-session** — creates fake credentials, backups, and scripts based on what commands the attacker runs
3. **Learns across sessions** — adapts the fake environment based on patterns from previous attackers
4. **Generates intelligence dossiers** — structured JSON per session with classification, commands, and OSINT enrichment
5. **Builds attacker profiles** — aggregates session history per IP with threat scoring

---

## Architecture

```
Attacker ──► Cowrie SSH (port 22) ──► cowrie.json
                                           │
                          ┌────────────────┼────────────────┐
                          ▼                ▼                ▼
                    Log Parser        Reactor.py        Adaptor.py
                    (sessions,        (real-time        (cross-session
                     commands,         honeyfs           environment
                     logins)           mutation)         evolution)
                          │                │                │
                          ▼                └────────┬───────┘
                    Classifier                      ▼
                    (bot/human,             Cowrie honeyfs/
                     intent, risk)          (fake filesystem)
                          │
                          ▼
                    Dossier Generator
                    (JSON per session)
                          │
                          ▼
                    OSINT Enrichment
                    (ipinfo.io)
                          │
                          ▼
                    Flask Dashboard
                    (sessions, intelligence,
                     live logs, IP profiles)
```

---

## Key Features

### Adaptive Deception — 3 Levels

| Level | Module | What It Does |
|-------|--------|-------------|
| Static | `deception.py` | Pre-planted fake assets: SQL dumps, API keys, `.env` files, nginx configs |
| Reactive | `reactor.py` | Files appear mid-session based on attacker commands |
| Adaptive | `adaptor.py` | Environment evolves based on previous attack history |

**Reactive triggers:**

| Attacker Command | MORPH Response |
|-----------------|----------------|
| `ls /var/www` | Plants `config.php` with fake DB credentials |
| `cat /etc/passwd` | Creates `.ssh/authorized_keys` with fake keys |
| `wget` / `curl` | Drops fake malware script in `/tmp/` |
| `find` / `locate` | Creates `db_backup_2024.sql.gz` in `/opt/backup/` |
| `ps aux` | Creates `.monitor` persistence artifact in `/tmp/` |

**Cross-session adaptation:**
- Backup targeted repeatedly → relocated to randomized path
- Shadow file targeted → replaced with crackable md5crypt hashes
- Bots detected → inflated `/etc/services` to waste scanner time
- Human exploit seen → fake WIP exploit planted in `/tmp/work/`

### Rule-Based Classifier

No ML. Pure logic. Classifies every session:

- **Type**: `bot` or `human`
- **Intent**: `recon` / `exploit` / `persistence`
- **Risk**: `low` / `medium` / `high`
- **matched_rules**: full audit trail of what triggered the classification

Bot detection rules: sub-second sessions, rapid commands (>1.5/sec), scanner sequences, credential stuffing, short probe sessions with no commands.

### IP Intelligence

Per-IP attacker profiles built from session history:
- Session count, first/last seen, type and intent breakdown
- Threat score: `(high_risk × 3) + (medium_risk × 1) + (persistence × 2)`
- OSINT enrichment: country, org/ASN, city, timezone via ipinfo.io
- Full command history across all sessions from that IP

### Flask Dashboard

- **Dashboard** — live stats, top attacker IPs, recent activity, intent distribution
- **Sessions** — server-side filtered and paginated, multi-select filters
- **Intelligence** — IP profiles with threat scores and OSINT data
- **Live Logs** — real-time Cowrie event stream, color-coded by event type
- **About** — project description and live stats

Dark theme, HTMX polling, no JS frameworks. Deployed behind nginx with basic auth.

---

## Tech Stack

- **Python 3.10** — core pipeline
- **Flask + HTMX** — web UI, live updates
- **Cowrie** — SSH honeypot backend
- **ipinfo.io** — free tier OSINT enrichment
- **nginx** — reverse proxy with basic auth
- **systemd** — service management for Cowrie, reactor, and Flask

---

## Project Structure

```
MORPH/
├── main.py                 # Pipeline orchestrator
├── pipeline.py             # Cron-safe pipeline (no Flask)
├── log_parser.py           # Cowrie JSON log parser
├── classifier.py           # Rule-based session classifier
├── dossier.py              # JSON dossier generator
├── deception.py            # Static fake asset creator
├── adaptor.py              # Cross-session learning engine
├── reactor.py              # Real-time honeyfs reaction engine
├── osint.py                # IP enrichment via ipinfo.io
├── ip_profiles.py          # Per-IP attacker profile builder
├── cleanup.py              # Dossier count management
├── app.py                  # Flask web UI + caching layer
├── fs.py                   # Cowrie patch: auto-registers honeyfs files
├── setup_honeyfs.py        # Populates fake filesystem content
├── populate_honeyfs.py     # Additional honeyfs bait files
├── update_cmdoutput.py     # Adds realistic ps aux output
├── morph-flask.service     # systemd service for Flask
├── install_flask_service.sh
├── cowrie-logrotate.conf   # Log rotation config
├── templates/
│   ├── base.html
│   ├── index.html          # Dashboard
│   ├── sessions.html       # Session list with filters
│   ├── dossier.html        # Session detail
│   ├── intelligence.html   # IP profiles list
│   ├── ip_detail.html      # Per-IP detail view
│   ├── live_logs.html      # Real-time event stream
│   ├── about.html          # Project info
│   └── _log_fragment.html  # HTMX partial
└── morph/
    ├── dossiers/           # Generated JSON dossiers (gitignored)
    ├── ip_profiles.json    # Cached IP profiles (gitignored)
    └── *.log               # Runtime logs (gitignored)
```

---

## Deployment Setup

### VPS Requirements
- Ubuntu 22.04, 1GB RAM minimum
- Ports: 22 (Cowrie via iptables), 80 (nginx), 443 (real SSH)

### Cowrie

```bash
git clone https://github.com/cowrie/cowrie.git ~/cowrie
cd ~/cowrie
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
pip install -e .
cp etc/cowrie.cfg.dist etc/cowrie.cfg
# Edit etc/cowrie.cfg: set hostname = web-prod-01
twistd --umask=0022 --pidfile=twistd.pid -n cowrie &
```

Redirect port 22 to Cowrie:
```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
netfilter-persistent save
```

### MORPH

```bash
git clone https://github.com/nisbh/MORPH.git ~/morph
cd ~/morph
pip install flask watchdog requests

# Apply Cowrie fs.py patch
cp fs.py ~/cowrie/src/cowrie/shell/fs.py

# Populate fake filesystem
python3 setup_honeyfs.py
python3 update_cmdoutput.py

# Install Flask as systemd service
sudo bash install_flask_service.sh

# Install log rotation
sudo cp cowrie-logrotate.conf /etc/logrotate.d/cowrie

# Set up cron pipeline (every 5 minutes)
crontab -e
# Add: */5 * * * * cd ~/morph && /path/to/python3 pipeline.py >> morph/pipeline.log 2>&1
```

### nginx (public dashboard access)

```bash
sudo apt install -y nginx apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd morph
# Create proxy config pointing to localhost:5000
sudo systemctl enable --now nginx
```

---

## Sample Dossier

```json
{
  "session_id": "acd0536692b9",
  "src_ip": "130.12.180.51",
  "start_time": "2026-03-31T06:58:43Z",
  "end_time": "2026-03-31T06:59:19Z",
  "duration_seconds": 35.8,
  "login_attempts": [
    {"username": "root", "password": "P", "success": true}
  ],
  "commands": [
    "chmod +x clean.sh; sh clean.sh; rm -rf clean.sh",
    "mkdir -p ~/.ssh; echo \"ssh-rsa AAAA...\" >> ~/.ssh/authorized_keys",
    "chmod -R go= ~/.ssh"
  ],
  "classification": {
    "type": "human",
    "intent": "persistence",
    "risk": "high",
    "matched_rules": [
      "recon_commands:uname,env,ss",
      "exploit_commands:chmod +x",
      "persistence_commands:authorized_keys,.ssh/",
      "execution_attempts",
      "persistence_risk"
    ]
  },
  "osint": {
    "city": "Aachen",
    "region": "North Rhine-Westphalia",
    "country": "DE",
    "org": "AS202412 Omegatech LTD",
    "timezone": "Europe/Berlin"
  },
  "generated_at": "2026-03-31T08:20:02Z"
}
```

---

## Notable Captures

Since deployment (March 2026):
- **19,700+ sessions** captured from **460+ unique IPs**
- **17,400+ bot sessions** — automated credential scanners
- **530+ persistence attempts** — attackers trying to establish backdoors
- **Top source:** Alibaba Cloud infrastructure (Malaysia) — 14,857 sessions
- **Most interesting:** Human attacker from Germany (Omegatech LTD) planted SSH backdoor key using hex-encoded command to evade logging

---

## Constraints

- Solo dev, single maintainer
- No ML — all classification is rule-based
- No paid APIs — OSINT via ipinfo.io free tier
- Cowrie-specific — not a generic honeypot framework

---

## Future Work

- [ ] AbuseIPDB integration for IP reputation scoring
- [ ] Telegram/Discord webhook alerts for high-risk sessions
- [ ] Behavior fingerprinting across sessions
- [ ] Attack prediction from early command patterns
- [ ] Lightweight embeddings for command similarity clustering

---

## License

MIT