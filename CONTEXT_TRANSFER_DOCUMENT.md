# MORPH Context Transfer and Continuation Guide

Last verified: 2026-10-18
Repository: `/home/nb/GitHub Projects/MORPH`
Branch: `main`
HEAD at handoff: `e5d4fb6` (`ui improvements`)
Remote status at handoff: `main` matches `origin/main`; worktree was clean before this document update.

This document is intended to let another AI model continue work without reconstructing the project from scratch. Treat the current source files as authoritative when this document or older documentation disagrees with them.

## 1. Project Identity and Goal

MORPH means Modular Reactive Polymorphic Honeypot. It is a solo-maintained adaptive SSH honeypot and threat-intelligence dashboard built on Cowrie.

The core problem is that a static honeypot is easy for attackers to fingerprint. Once recognized, attackers leave quickly and the resulting telemetry is shallow. MORPH attempts to increase attacker dwell time and intelligence value by changing the fake environment in response to attacker commands and prior attack history.

Primary objective:

- Capture attacker sessions through Cowrie.
- Classify each session as bot or human, with intent and risk.
- Plant believable bait during a session.
- Adapt the fake filesystem across sessions.
- Persist one structured dossier per session.
- Aggregate behavior by source IP and enrich it with OSINT.
- Present the results through a Flask dashboard.

Primary product metric: attacker dwell time.

Important design constraint: classification is deliberately rule-based. There is no ML model in the current implementation. The project is Cowrie-specific and uses the free ipinfo.io service for enrichment.

## 2. Current Technology Stack

- Python 3.10 is the documented runtime. The current workspace has Python 3.13 bytecode artifacts, so compatibility should be checked before using newer syntax or dependencies.
- Cowrie provides the SSH honeypot, JSON event log, fake filesystem, and filesystem metadata.
- Flask provides the server-rendered web UI.
- Jinja2 is used by Flask templates.
- HTMX provides polling and partial updates; there is no frontend JS framework.
- Leaflet and Leaflet MarkerCluster are loaded from unpkg in the map template.
- ipinfo.io supplies IP geolocation and organization data.
- nginx is intended as the public reverse proxy with basic authentication.
- systemd is intended to supervise the Flask service and Cowrie. The reactor is currently a separate long-running Python process unless separately supervised.
- cron is intended to run the batch analysis pipeline periodically.
- `watchdog` is listed in older documentation, but the current `reactor.py` uses a one-second polling loop and does not need watchdog.
- `requests` is used by the legacy `osint.py`; `ip_profiles.py` uses Python's standard-library `urllib` implementation.

Expected Python packages from the current README:

```text
flask
watchdog
requests
```

The code paths currently used by the main dashboard also require Flask and the standard library. Confirm the deployed environment rather than blindly installing every historical dependency.

## 3. Current Repository Inventory

### Core runtime modules

- `main.py`: batch orchestrator. Parses Cowrie logs, classifies sessions, writes dossiers, applies deception, adapts the environment, and performs cleanup.
- `log_parser.py`: parses Cowrie JSON-lines logs and aggregates events by session ID.
- `classifier.py`: rule-based bot/human, intent, and risk classification, including self-contained classifier tests.
- `dossier.py`: writes and loads JSON dossiers under `morph/dossiers/`.
- `deception.py`: creates static bait and applies per-session deception actions.
- `reactor.py`: polls Cowrie's JSON log in real time and plants files into `honeyfs` when command triggers match.
- `adaptor.py`: reads historical dossiers and modifies the environment based on recurring attack patterns.
- `ip_profiles.py`: builds per-source-IP aggregates and enriches them through ipinfo.io using `urllib`.
- `osint.py`: older standalone OSINT implementation using `requests`; it is not imported by `main.py` after the forced enrichment step was removed.
- `app.py`: Flask UI, caching, route handlers, map/timeline/command data, threat scoring, live Cowrie event parsing, and background IP enrichment.
- `cleanup.py`: bounds dossier storage at 5,000 files.
- `fs.py`: Cowrie filesystem patch intended to auto-register dynamically created honeyfs files.

### Setup and operations

- `setup_honeyfs.py`, `populate_honeyfs.py`: create/populate fake filesystem content.
- `update_cmdoutput.py`: adds realistic command output, especially process output.
- `morph-flask.service`: systemd unit for Flask.
- `install_flask_service.sh`: installs and starts the Flask systemd unit.
- `cowrie-logrotate.conf`: logrotate policy for Cowrie JSON logs.
- `install_logrotate.sh`: installs and debug-validates the logrotate policy.

### Templates

- `base.html`: shared shell and navigation.
- `index.html`: dashboard.
- `sessions.html`: filtered and paginated session list.
- `dossier.html`: individual session dossier.
- `intelligence.html`: aggregated IP profile table.
- `ip_detail.html`: individual IP intelligence page.
- `live_logs.html`: live event page.
- `_log_fragment.html`: HTMX live log partial.
- `_enrich_status.html`: HTMX enrichment progress partial.
- `map.html`: Leaflet geolocation view with risk-colored marker clusters.
- `timeline.html`: timeline view.
- `commands.html`: command analytics view.
- `about.html`: project/about view.

### Runtime data

- `morph/dossiers/*.json`: generated session dossiers; current workspace contains a small set of sample dossiers.
- `morph/stats.json`: persistent cumulative attack count and update timestamp.
- `morph/ip_profiles.json`: generated profile cache when present; normally ignored/generated data.
- `morph/*.log`: runtime logs for reactor, adaptor, deception, and Flask.
- `reactor.log`: current reactor log path in `reactor.py`.

There is no `pipeline.py` in the current repository, despite `README.md` still documenting it. Do not add or invoke it without first deciding whether a separate cron-safe entry point is actually needed. Current cron guidance must use `main.py` or a future explicitly created pipeline wrapper.

## 4. Runtime Paths and Deployment Assumptions

The current code is written for a native Linux Cowrie deployment, not the old Windows/WSL split. These hard-coded paths are important:

```text
Cowrie root:        /home/cowrie/cowrie/
Cowrie JSON log:    /home/cowrie/cowrie/var/log/cowrie/cowrie.json
Cowrie honeyfs:     /home/cowrie/cowrie/honeyfs/
Cowrie fs metadata: /home/cowrie/cowrie/src/cowrie/data/fs.pickle
Cowrie PID:         /home/cowrie/cowrie/twistd.pid
Cowrie Python:      /home/cowrie/cowrie/cowrie-env/bin/python3
fsctl:              /home/cowrie/cowrie/cowrie-env/bin/fsctl
MORPH root:         /home/cowrie/morph/ in the documented VPS setup
```

The local checkout is under `/home/nb/GitHub Projects/MORPH`, so some constants are deployment-specific rather than valid for this development checkout. In particular:

- `log_parser.py`, `app.py`, and `reactor.py` point to `/home/cowrie/cowrie/...`.
- `adaptor.py` uses `/home/cowrie/cowrie/honeyfs` and also contains a likely stale `DOSSIERS_PATH` pointing to `/home/cowrie/GitHub Projects/MORPH/dossiers/`; its actual history reads through `dossier.load_all()`.
- `deception.py` writes under `/home/cowrie/cowrie/fake_assets` and `/home/cowrie/cowrie/fake_fs`.
- `morph-flask.service` assumes `/home/cowrie/morph` and the Cowrie virtualenv.

Before deploying to a new host, centralize or audit these paths. Avoid changing them casually in only one module because the reactor, adaptor, app, and Cowrie patch must agree.

## 5. End-to-End Architecture and Data Flow

```text
Attacker
  -> Cowrie SSH service
  -> cowrie.json JSON-lines event log
       |                         |
       |                         +-> reactor.py polls new events every 1 second
       |                              and writes reactive bait into honeyfs
       |
       +-> main.py batch processing
            1. parse_cowrie_log()
            2. classify_session()
            3. dossier.generate()
            4. deception.initialize() and deception.adapt()
            5. adaptor.adapt_environment()
            6. cleanup if dossier count exceeds 5,000
            7. update morph/stats.json

Generated dossiers
  -> ip_profiles.build_ip_profiles()
  -> optional/background ipinfo.io enrichment
  -> Flask dashboard caches and views
```

The current design intentionally separates two adaptation timescales:

1. Reactive adaptation: `reactor.py` responds during a live session.
2. Historical adaptation: `adaptor.py` reads prior dossiers during batch processing and evolves the fake environment for future sessions.

The Flask app is a read-oriented dashboard with a background enrichment action. Recent history changed `main.py` to be cron-safe: it no longer starts Flask after processing, and it no longer forces OSINT enrichment for every batch run.

## 6. Batch Pipeline: Verified Current Behavior

`main.py` exposes `process_sessions()` and runs it when executed directly.

### Stage 1: Parse

`log_parser.parse_cowrie_log(COWRIE_LOG)` reads the entire JSON-lines log. Events without a `session` are ignored. Malformed JSON lines are warned about and skipped.

Each session contains:

- `session_id`
- `src_ip`
- `start_time` and `end_time`
- `duration_seconds`
- `login_attempts` with username, password, and inferred success
- `commands` from event `input`
- `downloads` from event `url`

Timestamps are ISO-parsed with trailing `Z` converted to UTC offset notation. Duration is the difference between the earliest and latest event timestamp.

### Stage 2: Classify

`classifier.classify_session()` returns:

```json
{
  "type": "bot|human",
  "intent": "recon|exploit|persistence",
  "risk": "low|medium|high",
  "matched_rules": []
}
```

Bot signals and scores:

- Sub-second session: +10.
- Less than 10 seconds with no commands: +6, rule `short_probe_no_commands`.
- Less than 2 seconds with no commands: +8, rule `instant_disconnect`.
- Less than 5 seconds with more than three logins: +8.
- More than 1.5 commands per second: +5.
- A command repeated at least three times: +4.
- Known command sequences such as `uname -a`, `/etc/passwd`, `/proc/cpuinfo`, or download sequences: +5.
- Scanner fingerprint containing `whoami`, `id`, and `uname`: +4.
- More than five login attempts: +3.
- One failed login, no commands, and disconnect under 15 seconds: +5, rule `single_failed_login_disconnect`.
- At least three login attempts with no commands: +6, rule `credential_stuffing`.
- At least two passwords matching common bot-password fragments: +3.
- Known scanner command names: +3.

Human signals:

- More than 60 seconds with at least two varied commands: +4.
- Interactive commands such as `vim`, `less`, `man`, or `top`: +2.
- More than two `cd` commands and more than two `ls` references: +2.
- Human score is forced to zero when bot evidence exists and fewer than two commands were issued. This is Rule D, intended to prevent a tiny amount of interaction from overriding scanner evidence.

Intent is selected by the highest score from recon, exploit, and persistence. Recon is the default when all intent scores are zero. Pattern lists include reconnaissance commands, download/execution commands, persistence locations, and scanner tools.

Risk scoring:

- Downloads: +2.
- Execution patterns such as `./`, `python -c`, `bash -c`, or `chmod +x`: +2.
- Download plus execution: +2.
- Persistence matches: +3.
- `/etc/shadow`: +2.
- Privilege escalation strings: +1.
- Risk is high at 5 or more, medium at 2-4, and low below 2.

### Stage 3: Generate dossiers

`dossier.generate()` writes one JSON file at `morph/dossiers/<session_id>.json`. It includes the session fields, classification, optional adaptation report, an initially empty `osint` object, and `generated_at`.

### Stage 4: Per-session deception

`deception.initialize()` creates baseline fake content, then `deception.adapt(session, classification)` applies session-specific deception. Actions are logged to `morph/deception.log`.

### Stage 5: Historical adaptation

`adaptor.adapt_environment()` loads all dossiers and tracks risk/type/intent distributions, common commands, targeted paths, shadow attempts, backup attempts, and downloads.

Current historical rules:

- Any backup targeting triggers relocation/adaptation of backup bait.
- At least two shadow/passwd attempts triggers crackable fake shadow content.
- At least one bot session triggers an expanded fake `/etc/services` list.
- At least one human session classified as exploit triggers a fake unfinished exploit script.

### Stage 6: Cleanup and counters

If dossier count exceeds 5,000, `cleanup.run_cleanup()` deletes the oldest dossiers by `generated_at` until 5,000 remain. At more than 3,000 it reports a warning; at 3,000 or fewer it reports no action. `main.py` currently invokes cleanup conditionally and updates the cumulative attack count in `morph/stats.json`.

Important behavior: `main.py` processes the full log on each run and generates/overwrites dossiers by session ID. A future incremental-processing design may be needed as the log grows.

## 7. Reactive Deception Rules

`reactor.py` starts at the end of the existing log, then polls for new lines. It does not replay old commands on startup.

Triggers and bait:

- `ls /var/www`, `cd /var/www`, or `ls -la /var/www`: `var/www/html/config.php` and `var/www/html/.git/config`.
- `ps aux`, `ps -ef`, `top`, or `htop`: `tmp/.monitor`.
- `cat /etc/passwd` or `cat /etc/shadow`: `home/deploy/.ssh/authorized_keys` and `home/deploy/.bash_history`.
- `find /`, `find .`, or `locate`: `opt/backup/db_backup_2024.sql.gz` and `opt/scripts/backup.sh`.
- `wget` or `curl` patterns: a randomized hidden shell file under `tmp/` containing defanged malware placeholder content.

The current reactor writes files directly to honeyfs and checks whether they already exist. The documented older behavior of running `fsctl` and sending SIGHUP is not visible in the current `reactor.py`; verify the Cowrie `fs.py` patch and reload semantics on the target host before assuming newly written files are immediately visible to active sessions.

## 8. Static Deception Assets

`deception.py` creates believable but synthetic artifacts such as:

- SQL backups with users, hashes, and API tokens.
- API-key files containing fake AWS, Stripe, GitHub, Slack, SendGrid, and Twilio values.
- `.env` files with fake database, Redis, mail, AWS, JWT, and internal API credentials.
- Fake internal documentation and service-account credential files.

These values are deception content. They must remain clearly synthetic and must never contain real credentials. Treat any accidental real-looking secret in the repository as a security review item.

## 9. IP Profiles and OSINT

`ip_profiles.build_ip_profiles()` aggregates dossiers by `src_ip` and stores:

- Total sessions.
- First and last seen.
- Type, intent, and risk breakdowns.
- Primary type and intent.
- Highest observed risk.
- Total and unique commands.
- Command frequencies.
- Session IDs.
- OSINT data.

`ip_profiles.enrich_ip_profiles()` loads cached profiles, preserves existing OSINT, skips private/reserved/local IPs with an `is_private` record, and calls `https://ipinfo.io/<ip>/json` for public IPs. It reports progress through a callback and persists to `morph/ip_profiles.json`.

The app's threat score is:

```text
(high-risk sessions * 3) + medium-risk sessions + (persistence-intent sessions * 2)
```

The app assigns visual bands of zero/minimal, 1-5 low, 6-15 medium, and 16+ critical. Profiles are sorted by threat score or other selected ordering in the intelligence view.

There are two OSINT implementations. The active profile implementation uses `urllib`; `osint.py` is a legacy standalone implementation using `requests` and includes latitude/longitude, Tor, and VPN heuristics. Do not merge the two casually. First decide which one is authoritative, then remove duplication or explicitly route all callers through one implementation.

Recent decision: forced dossier-wide OSINT enrichment was removed from `main.py` so cron processing does not block on network calls. Enrichment is now an app-triggered/background concern.

## 10. Current Flask Routes

Verified route surface in `app.py`:

- `GET /`: dashboard.
- `GET /map`: Leaflet map of IPs with valid OSINT coordinates.
- `GET /timeline`: attack timeline.
- `GET /commands`: command analytics.
- `GET /sessions`: filtered, paginated sessions. Filters include type, risk, and intent, with query parameters and active filter state.
- `GET /intelligence`: aggregated IP profiles with sorting/pagination.
- `GET /intelligence/<ip>`: per-IP detail and session history.
- `POST /intelligence/enrich`: starts background enrichment if one is not already running.
- `GET /intelligence/enrich/status`: returns progress state for HTMX.
- `GET /dossier/<session_id>`: dossier detail.
- `GET /live-logs`: live Cowrie event page.
- `GET /about`: project/about page.
- `GET /api/logs`: HTMX log fragment endpoint.

App behavior and UI decisions:

- Dashboard stat cards are links to relevant filtered views.
- Last attack time is derived from dossier timestamps and cached for 60 seconds.
- IP addresses link to per-IP intelligence pages unless unknown.
- Sessions are paginated at 50 per page; per-IP session lists use 20; intelligence uses 50.
- Multiple app caches are used for dossiers, sessions, dashboard data, IP profiles, map data, timeline data, command data, and stats.
- Enrichment status is protected by a lock and reports `total`, `done`, and `running`.
- Live logs parse up to 30 recent Cowrie JSON events and recognize connect, failed login, successful login, command, and session close events.
- The IP detail CSS was changed to prevent horizontal overflow, wrap long command cells, use a responsive grid, and collapse to one column below 768px.
- The map uses dark CARTO tiles, Leaflet MarkerCluster, risk-colored markers, escaped popup values, and automatic bounds fitting.

## 11. Recent Decisions and History

The latest relevant commits, newest first:

- `e5d4fb6` (`ui improvements`, 2026-05-06): added Leaflet MarkerCluster styles/scripts, custom cluster icons, risk-colored markers, and popup marker handling.
- `5efaed6` (`map not rendering`): corrected map template behavior before the clustering improvement.
- `54ee485` (`updates to map feature`): expanded OSINT support needed by the map.
- `4604b57` (`updated to run correct cron job`): removed the Flask server startup from `main.py`; direct execution now only processes sessions, which makes it suitable for scheduled runs.
- `035f07a` (`removed forced osint enrichment step`): removed `osint.enrich_all_dossiers()` from the batch pipeline so scheduled processing is not forced to perform external API calls.

These decisions imply that production operation should use separate processes/jobs:

1. Cowrie service.
2. `reactor.py` long-running process.
3. Flask systemd service.
4. Scheduled `main.py` batch job.

Do not restore the old behavior where `main.py` starts Flask unless the deployment model is intentionally changed.

## 12. Validation Already Implemented

`classifier.py` contains seven self-tests covering:

1. Bot by rapid command speed.
2. Bot by scanner sequence.
3. Human classification.
4. Rule A: short probe without commands.
5. Rule B: one failed login and quick disconnect.
6. Rule C: credential stuffing.
7. Rule D: human override hardening.

`integration_verify.py` contains six checks:

1. Module imports.
2. Classifier Rule A.
3. Cleanup utility.
4. App threat scoring and Cowrie event parsing when the log exists.
5. Required templates.
6. Configuration files.

Useful commands:

```bash
python3 classifier.py
python3 cleanup.py
python3 integration_verify.py
python3 -m py_compile app.py ip_profiles.py main.py classifier.py cleanup.py
python3 -m py_compile *.py
```

The historical documentation reports all feature-wave checks passing, including 7/7 classifier tests, 6/6 integration categories, syntax checks, template checks, and configuration checks. Re-run them in the current environment rather than treating the historical result as proof after further edits.

## 13. Deployment Model

Documented VPS assumptions:

- Ubuntu 22.04, approximately 1 GB RAM minimum.
- Cowrie listens on its configured port, commonly 2222.
- iptables redirects public port 22 to Cowrie; real administrative SSH is expected on another port such as 443 in the older README example.
- nginx exposes the dashboard and applies basic auth.
- Flask binds to `0.0.0.0:5000` in the systemd unit.
- Cowrie and Flask are run as the `cowrie` user in the documented setup.
- Cowrie logrotate is daily, retains 14 rotations, compresses old logs, uses delay compression, rotates above 50 MB, uses copytruncate, and creates a 0644 file.

The current `morph-flask.service` starts Flask from `/home/cowrie/morph` with the Cowrie virtualenv Python and restarts on failure. `install_flask_service.sh` copies the unit into `/etc/systemd/system`, reloads systemd, enables, starts, and prints status.

The current logrotate installer requires root, copies `cowrie-logrotate.conf` to `/etc/logrotate.d/cowrie`, sets mode 0644, and runs `logrotate --debug`.

## 14. Known Gaps, Risks, and Documentation Corrections

These are important continuation items, not claims that the current system is broken:

- `CONTEXT_TRANSFER_DOCUMENT.md`, before this update, described Windows/WSL files such as `reactor_wsl.py` and `sync.py`; those files are absent. Native Linux is the current model.
- `README.md` references nonexistent `pipeline.py`; its cron command is therefore stale. Replace it with a verified `main.py` command or add a deliberate wrapper.
- `main.py` imports `app` even though it no longer starts Flask. This may be harmless but creates unnecessary dependency coupling for cron and can fail if Flask is absent. Consider moving the import or separating the batch entry point.
- The batch parser rereads the whole Cowrie log every run. With a large active deployment, this can become slow and can repeatedly classify old sessions. Add incremental state or a processed-session strategy before scale becomes a problem.
- Dossier cleanup is based on generated timestamps and deletes files without an archive. Confirm that this retention policy is acceptable for forensic use.
- Dossier filenames are derived from session IDs. Validate session IDs before using them in paths if Cowrie input trust assumptions change.
- OSINT calls are external, rate-limited, and potentially unavailable. Preserve nonblocking behavior and add retries/backoff only with care.
- The profile and legacy OSINT modules duplicate responsibilities and disagree on implementation details. Consolidate later.
- The active profile enrichment currently stores city, region, country, flag, org, timezone, and hostname but the map requires coordinates. Verify that coordinates are actually present in the active profile data path. The legacy `osint.py` explicitly parses `loc`; this mismatch may explain empty maps on some deployments.
- `ip_profiles.py` generates country flags with Unicode. The project preference is to avoid emojis in UI/content; decide whether to replace visible flags with country codes or keep them only where intentional.
- Reactor polling starts at end-of-file and has no explicit log rotation/inode reset handling. After Cowrie log rotation, verify that it notices truncation or replacement; otherwise it may stop seeing events or read from an invalid offset.
- Dynamic honeyfs writes may require Cowrie filesystem metadata refresh. Verify `fs.py`, `fs.pickle`, `fsctl`, and SIGHUP behavior on the deployed Cowrie version.
- There are no conventional pytest tests; tests are executable scripts and functions. Add focused automated tests before major classifier or parser changes.
- The app uses external Leaflet assets from unpkg. Consider local pinning or an integrity/offline strategy for a security dashboard.
- The README includes historical deployment statistics and a specific attack story. Keep those labeled as historical snapshots and avoid presenting them as current live totals without verification.

## 15. Prioritized Continuation Roadmap

### Priority 0: Establish a trustworthy baseline

1. Run all validation commands listed above.
2. Record failures caused by environment paths, missing Cowrie files, or missing packages separately from code failures.
3. Check `git status` before any edit and preserve unrelated user work.
4. Confirm the current Flask routes render with a test client using the checked-in sample dossiers.
5. Verify the map data shape and whether active profiles include latitude/longitude.

### Priority 1: Make deployment configuration coherent

1. Remove stale Windows/WSL references from README and all docs.
2. Decide whether `main.py` or a new `pipeline.py` owns cron execution. Do not document a nonexistent command.
3. Move Cowrie/MORPH paths into one configuration module or environment variables.
4. Separate batch imports from Flask imports so cron does not require web-only dependencies.
5. Document how to supervise `reactor.py` with systemd and how to handle Cowrie log rotation.

### Priority 2: Improve correctness and scale

1. Add incremental log processing or a durable high-water mark.
2. Make parser handling resilient to rotated/truncated logs and malformed events.
3. Add tests for timestamp boundaries, duplicate sessions, missing fields, malformed JSON, command-rate edge cases, and classifier tie behavior.
4. Add a dry-run mode for cleanup and adaptation.
5. Add atomic writes for dossiers, stats, and profile caches to avoid partial JSON on interruption.
6. Review concurrency around profile cache refresh and background enrichment.

### Priority 3: Unify intelligence data

1. Choose `ip_profiles.py` or `osint.py` as the single OSINT implementation.
2. Preserve coordinates, privacy indicators, organization, and cache/error state in one schema.
3. Add abuse reputation integration, likely AbuseIPDB, only after API-key/configuration handling is designed.
4. Add behavior fingerprints across sessions and IPs.
5. Add command similarity clustering or lightweight embeddings only after the rule-based baseline is measured.

### Priority 4: Improve analyst workflow

1. Add high-risk alerts through a configurable webhook, such as Telegram or Discord.
2. Add dossier export and filtering by time range, IP, threat score, and matched rule.
3. Add a clear distinction between observed facts, inferred classification, and external enrichment.
4. Add retention/archive controls for investigations that must outlive the 5,000-dossier limit.
5. Add health/status reporting for Cowrie, reactor, batch freshness, enrichment failures, and log rotation.

## 16. Recommended Next Model Working Method

When continuing from this handoff:

1. Start from the concrete user request and the nearest owning module.
2. Read the relevant current source and neighboring test before editing.
3. State one falsifiable local hypothesis and one cheap validation check.
4. Make the smallest edit that tests the hypothesis.
5. Run a focused executable validation immediately after the edit.
6. Only then widen to adjacent modules or UI verification.
7. Keep documentation synchronized with actual files, especially entry points and deployment commands.

Preserve the existing visual direction: dark operational dashboard, restrained low-contrast hover states, compact data-dense layouts, responsive tables, and no unnecessary decorative UI. The user prefers no emojis in UI or content.

## 17. Short Handoff Summary

MORPH is a functioning Cowrie-based adaptive honeypot with three deception layers, a rule-based classifier, JSON dossiers, IP aggregation, optional OSINT enrichment, a Flask/HTMX dashboard, a live reactor, map/timeline/command views, cleanup, and deployment helpers. The most recent work improved the Leaflet map and changed the batch process to be cron-safe by removing Flask startup and forced OSINT enrichment. The next model should first validate the current environment, correct stale documentation and path/configuration coupling, verify map coordinates, and then improve incremental processing, tests, OSINT unification, and service supervision.
