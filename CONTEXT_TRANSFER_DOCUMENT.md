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
Attacker → Cowrie → cowrie.json → Parser → Classifier → Dossier
                                                        ↓
                                              Adaptor (cross-session)
                                                        ↓
                                            Reactor (real-time honeyfs)
                                                        ↓
                                                   Flask UI
```

**Primary metric:** attacker dwell time
**Differentiator:** adaptive behavior based on attacker actions

---

## 4. COMPONENTS — STATUS

### Capture — Cowrie
- Logs: commands, sessions, login attempts
- Log location: `/home/nisar/cowrie/var/log/cowrie/cowrie.json` (Fedora)
- Status: ✅ Built and tested

### Parser — `log_parser.py`
- Reads `cowrie.json` line by line
- Groups events by session ID
- Extracts: IP, timestamps, login attempts, commands, downloads, duration
- Status: ✅ Built and tested

### Classifier — `classifier.py`
- Rule-based, no ML
- Output:
  - type: `bot` / `human`
  - intent: `recon` / `exploit` / `persistence`
  - risk: `low` / `medium` / `high`
  - matched_rules: list of triggered rule names
- Known issue: bot detection not triggering on rapid command input — needs tuning
- Status: ✅ Built, ⚠️ bot detection needs fix

### Dossier Generator — `dossier.py`
- Input: session + classification
- Output: JSON file per session in `dossiers/`
- Includes: session timeline, commands, intent, risk, behavior pattern, adaptation report
- Functions: `generate()`, `load_all()`
- Status: ✅ Built and tested

### Deception — Level 1 (Cowrie config)
- Hostname: `web-prod-01`
- Fake users in `honeyfs/etc/passwd`: deploy, jenkins
- Fake `honeyfs/home/deploy/.bash_history` with credentials
- Fake `honeyfs/var/www/html/index.html`
- Fake `honeyfs/opt/scripts/backup.sh`
- Fake crontab in `honeyfs/var/spool/cron/root`
- `honeyfs/etc/hostname` → `web-prod-01`
- `honeyfs/etc/issue` → Ubuntu 22.04.3 LTS
- Cowrie `userdb.txt`: accepts any password for root
- Status: ✅ Built and tested

### Deception — Level 2 — `reactor_wsl.py` → rename to `reactor.py` on Fedora
- Watches live `cowrie.json` for new events using watchdog
- Triggers reactions based on attacker commands in real time
- Writes new files into honeyfs
- Updates `fs.pickle` via fsctl subprocess so Cowrie serves new files immediately
- Sends SIGHUP to Cowrie after pickle update to reload
- Reactions:
  - `ls /var/www` → creates `config.php` with fake DB creds + `.git/config`
  - `cat /etc/passwd` or `cat /etc/shadow` → creates `deploy/.ssh/authorized_keys`
  - `ps aux` or `top` → creates `tmp/.monitor`
  - `wget` / `curl` → creates random `.sh` file in `/tmp/`
  - `find` / `locate` → creates fake `.sql.gz` backup file
- Logs to: `morph/reactor.log`
- Status: ✅ Built and tested (full reactive loop verified)

### Deception — Level 3 — `adaptor.py`
- Reads all previous dossiers on startup
- Modifies honeyfs before each new session based on attack history
- Rules:
  - `/opt/backup` targeted 4+ times → relocate to randomized path
  - 2+ sessions tried `/etc/shadow` → replace with fake crackable shadow file
  - Bot detected previously → inflate `honeyfs/etc/services`
  - Previous human+exploit → plant fake WIP exploit in `/tmp/work/`
- Generates adaptation report added to each dossier
- Logs to: `morph/adaptor.log`
- Status: ✅ Built and tested (2 adaptations confirmed in honeyfs)

### Flask UI — `app.py`
- Routes:
  - `GET /` → dashboard (session counts, risk summary, recent dossiers)
  - `GET /sessions` → session table with classification badges
  - `GET /dossier/<session_id>` → full dossier detail
  - `GET /live-logs` → latest 20 log lines (HTMX polling)
  - `GET /api/logs` → raw log API
  - `GET /adaptations` → adaptation history
- Dark theme, no external CSS frameworks
- Status: ✅ Built and tested

### Pipeline — `main.py`
- Run order:
  1. Sync log (currently manual, sync.py not yet built)
  2. Parse sessions
  3. Classify sessions
  4. Generate dossiers
  5. Run adaptor (cross-session environment changes)
  6. Start Flask
  7. Note: reactor runs independently as separate process

---

## 5. WHAT IS NOT BUILT YET

- `sync.py` — auto log sync, replaces manual `cp` command
- Bot classifier fix — rapid commands not triggering bot type
- OSINT enrichment — `ipinfo.io` integration for IP geolocation + ASN
- Behavior fingerprinting (post-MVP)
- Attack prediction (post-MVP)
- Embeddings / lightweight ML (post-MVP)

---

## 6. CONSTRAINTS

- Solo dev
- No paid APIs
- No heavy ML
- Keep modular + simple
- Rule-based only for MVP

---

## 7. EXCLUDED (FOR NOW)

- Deep learning
- Reinforcement learning
- LLM pipelines
- SIEM integration
- Multi-node systems

---

## 8. NEXT STEPS (ORDERED)

1. Fresh Cowrie install on Fedora (dnf)
2. Clone MORPH repo into `/home/nisar/morph/`
3. Fix file paths (remove WSL-specific paths, use native Linux paths)
4. Build `sync.py` (auto log sync, no longer needed on same filesystem)
5. Fix bot classifier
6. OSINT enrichment via `ipinfo.io`
7. VPS deployment

---

## 9. ENVIRONMENT — FEDORA (NEW)

```
/home/nisar/
├── cowrie/                  ← Cowrie installation
│   ├── cowrie-env/          ← Python virtualenv
│   ├── honeyfs/             ← Fake filesystem served to attackers
│   ├── etc/cowrie.cfg       ← Cowrie config
│   ├── etc/userdb.txt       ← Login credentials
│   ├── src/cowrie/data/fs.pickle  ← Virtual filesystem registry
│   └── var/log/cowrie/cowrie.json ← Live session log
│
└── morph/                   ← MORPH project
    ├── log_parser.py
    ├── classifier.py
    ├── dossier.py
    ├── adaptor.py
    ├── reactor.py
    ├── app.py
    ├── main.py
    ├── templates/
    ├── dossiers/            ← Generated, gitignored
    ├── reactor.log          ← Generated, gitignored
    └── adaptor.log          ← Generated, gitignored
```

**Single user:** `nisar`
**Single filesystem:** no WSL, no path bridging, no manual sync
**Cowrie log path:** `/home/nisar/cowrie/var/log/cowrie/cowrie.json`
**fs.pickle path:** `/home/nisar/cowrie/src/cowrie/data/fs.pickle`
**twistd.pid path:** `/home/nisar/cowrie/twistd.pid`

---

## 10. COWRIE INSTALL — FEDORA

```bash
sudo dnf install -y git python3 python3-virtualenv openssl-devel \
  libffi-devel gcc python3-devel

git clone https://github.com/cowrie/cowrie ~/cowrie
cd ~/cowrie
virtualenv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Then apply all Level 1 honeyfs changes and userdb.txt config from Section 4 above.

---

## 11. KEY COPILOT PROMPTS (FOR CONTINUATION)

All original prompts remain valid. When continuing on Fedora, update any hardcoded paths:
- Replace `\\wsl$\Ubuntu\home\nisar\morph\` with `/home/nisar/morph/`
- Replace `/home/cowrie/cowrie/` with `/home/nisar/cowrie/`
- `reactor_wsl.py` becomes `reactor.py`

---

## 12. TONE + STRATEGY

- No fluff, no hype, practical > fancy
- Primary metric: attacker dwell time
- Differentiator: adaptive behavior based on attacker actions
- MORPH = lightweight adaptive honeypot that captures attacker actions,
  classifies behavior (rule-based), adapts environment,
  and generates structured attacker dossiers
