#!/usr/bin/env python3
"""
setup_honeyfs.py - Seed Cowrie with a realistic Ubuntu 22.04 web-server filesystem.

This script:
1) writes high-value bait files into honeyfs
2) registers standard Linux paths and bait files into fs.pickle via fsctl
3) prints a summary of what was written and registered
"""

from __future__ import annotations

import random
import subprocess
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

FSCTL = Path("/home/cowrie/cowrie/cowrie-env/bin/fsctl")
PICKLE = Path("/home/cowrie/cowrie/src/cowrie/data/fs.pickle")
HONEYFS_ROOT = Path("/home/cowrie/cowrie/honeyfs")
HOSTNAME = "web-prod-01"

STANDARD_DIRS = [
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/mnt",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/usr/bin",
    "/usr/local",
    "/usr/sbin",
    "/usr/share",
    "/var/www",
    "/var/www/html",
    "/var/log",
    "/var/lib",
    "/home/deploy",
    "/home/ubuntu",
    "/root/.ssh",
]

ENV_FILE = """DB_HOST=db.internal
DB_USER=webapp
DB_PASS=Wbp@ss_Pr0d_2024
AWS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET=sk_live_51HG8kEXAMPLE
"""

OS_RELEASE = """NAME=\"Ubuntu\"
VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"
VERSION_ID=\"22.04\"
HOME_URL=\"https://www.ubuntu.com/\"
SUPPORT_URL=\"https://help.ubuntu.com/\"
BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"
PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy
"""

HOSTS_FILE = """127.0.0.1 localhost
10.0.1.10 db.internal
10.0.1.15 jenkins.internal
10.0.1.20 monitoring.internal
"""

AUTHORIZED_KEYS = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDeu8DcJbXc8p2GJvKjY2tN2Hh8n0KaP2CJH4GjYQW9U2i5T4Xn9c3Y6J0f8k7M1f2Y8N5v8xW5o8uN0P7bA9nC1Y3fK2mQ6xV8kD9wL3yQ8H0bV5P2kN8sU4eA9fR2pL6jW4xQ8tN3cE2vK5rL9mA2cD4nG8pQ1tS5uW7yZ0bC3dF6gH8jK1mN4pR7tV0xY3zA6bD9eF2gH5jK8mN1pQ4tU7wX0z deploy@bastion-prod
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID9W3X2j6m7q5k4t8n1v0b3c2d5f6g7h8j9k0l1m2n3 ops-laptop-2024
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDg3j1XvQ9hL2mN5pR8tU1wX4zA7cD0eF3gH6jK9mN2pQ5tV8xY1zB4dE7fG0hJ3kL6mN9pQ2tR5uV8xY1zA4cF7hJ0kL3mN6pQ9tR2uV5xY8zA1cD4fG7hJ0kL3mN6pQ9 ci-runner@jenkins.internal
"""

INDEX_PHP = """<?php
declare(strict_types=1);

$env = parse_ini_file(__DIR__ . '/.env', false, INI_SCANNER_RAW);
$dbHost = $env['DB_HOST'] ?? 'localhost';
$dbUser = $env['DB_USER'] ?? 'webapp';
$dbPass = $env['DB_PASS'] ?? '';
$dbName = 'webapp_prod';

$mysqli = @new mysqli($dbHost, $dbUser, $dbPass, $dbName, 3306);
if ($mysqli->connect_errno) {
    http_response_code(500);
    echo "Application temporarily unavailable.";
    exit;
}

$result = $mysqli->query("SELECT title, body, published_at FROM posts WHERE published = 1 ORDER BY published_at DESC LIMIT 5");
$posts = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
?>
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Internal Portal</title>
</head>
<body>
  <h1>Internal Portal</h1>
  <?php foreach ($posts as $post): ?>
    <article>
      <h2><?= htmlspecialchars($post['title']) ?></h2>
      <p><?= nl2br(htmlspecialchars($post['body'])) ?></p>
      <small><?= htmlspecialchars($post['published_at']) ?></small>
    </article>
  <?php endforeach; ?>
</body>
</html>
"""

APP_CONFIG = """app:
  name: web-portal
  environment: production
  bind: 0.0.0.0:8080

database:
  host: db.internal
  port: 3306
  name: webapp_prod
  user: webapp
  password: \"Wbp@ss_Pr0d_2024\"

redis:
  host: 10.0.1.25
  port: 6379

external_apis:
  billing_url: https://billing.internal/api
  billing_token: \"bill_prod_9f2e1c8b2a\"
  monitoring_url: http://monitoring.internal:9090
  sentry_dsn: \"https://5d4f0c12abcde@sentry.internal/42\"
"""

DEPLOY_SH = """#!/usr/bin/env bash
set -euo pipefail

APP_ROOT=\"/opt/app\"
RELEASE_DIR=\"$APP_ROOT/releases/$(date +%Y%m%d%H%M%S)\"
REPO_URL=\"git@10.0.1.15:platform/web-portal.git\"
DB_HOST=\"10.0.1.10\"
WEB_NODE=\"10.0.1.20\"
MONITOR_NODE=\"10.0.1.20\"

echo \"[deploy] Preparing release directory: $RELEASE_DIR\"
mkdir -p \"$RELEASE_DIR\"

echo \"[deploy] Fetching source from $REPO_URL\"
git clone --depth 1 \"$REPO_URL\" \"$RELEASE_DIR\"

echo \"[deploy] Installing dependencies\"
cd \"$RELEASE_DIR\"
composer install --no-dev --optimize-autoloader
php artisan config:cache

echo \"[deploy] Running migrations against $DB_HOST\"
php artisan migrate --force --database=mysql

echo \"[deploy] Switching current symlink\"
ln -sfn \"$RELEASE_DIR\" \"$APP_ROOT/current\"

echo \"[deploy] Reloading php-fpm and nginx on $WEB_NODE\"
ssh deploy@\"$WEB_NODE\" \"sudo systemctl reload php8.1-fpm && sudo systemctl reload nginx\"

echo \"[deploy] Sending deployment marker to monitoring node $MONITOR_NODE\" 
curl -sS -X POST \"http://$MONITOR_NODE:9090/deployments\" \\
  -H \"Content-Type: application/json\" \\
  -d '{\"service\":\"web-portal\",\"status\":\"success\"}'

echo \"[deploy] Deployment complete\"
"""


def _fmt_syslog_time(ts: datetime) -> str:
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


def generate_bash_history() -> str:
    """Generate realistic root shell history over several weeks."""
    rng = random.Random(22043)
    commands = [
        "apt update",
        "apt upgrade -y",
        "apt autoremove -y",
        "systemctl status nginx --no-pager",
        "systemctl restart nginx",
        "systemctl restart php8.1-fpm",
        "tail -n 100 /var/log/nginx/error.log",
        "tail -n 200 /var/log/auth.log",
        "journalctl -u nginx --since '2 hours ago'",
        "journalctl -u mysql --since '1 day ago'",
        "mysql -u root -p -e \"SHOW DATABASES;\"",
        "mysql -u root -p -e \"SELECT user,host FROM mysql.user;\"",
        "mysql -u root -p webapp_prod -e \"SELECT count(*) FROM users;\"",
        "mysqldump -u root -p webapp_prod > /var/backups/webapp_prod.sql",
        "cd /var/www/html && git status",
        "cd /var/www/html && git pull origin main",
        "cd /var/www/html && composer install --no-dev",
        "php -v",
        "php -m | grep -i mysqli",
        "ls -lah /etc/nginx/sites-enabled",
        "nano /etc/nginx/sites-available/web-portal.conf",
        "nginx -t",
        "systemctl reload nginx",
        "crontab -l",
        "cat /opt/app/config.yml",
        "vim /opt/app/config.yml",
        "bash /opt/scripts/deploy.sh",
        "find /var/log -type f -name '*.log' | wc -l",
        "grep -R \"db.internal\" /opt/app -n",
        "ss -tulpen | grep -E '22|80|443|3306'",
        "df -h",
        "free -m",
        "uptime",
        "last -n 15",
        "cat /etc/hosts",
        "cat /etc/os-release",
        "chmod 700 /root/.ssh",
        "chmod 600 /root/.ssh/authorized_keys",
        "systemctl enable nginx",
        "systemctl status mysql --no-pager",
        "mysqladmin -u root -p ping",
        "tail -f /var/log/nginx/access.log",
        "exit",
    ]

    now = datetime.utcnow()
    current = (now - timedelta(days=46)).replace(hour=7, minute=15, second=0, microsecond=0)
    lines: list[str] = []

    for command in commands:
        lines.append(f"#{int(current.timestamp())}")
        lines.append(command)
        current += timedelta(hours=rng.randint(6, 28), minutes=rng.randint(0, 59))

    return "\n".join(lines) + "\n"


def generate_auth_log() -> str:
    """Generate 30 days of mixed successful and failed SSH auth activity."""
    rng = random.Random(220422)

    attacker_ips = [
        "45.133.172.35",
        "91.240.118.74",
        "103.77.192.88",
        "104.248.172.91",
        "138.68.95.14",
        "162.142.125.199",
        "185.220.101.29",
        "193.32.162.75",
        "198.44.136.221",
        "203.0.113.57",
    ]
    internal_ips = ["10.0.1.20", "10.0.1.15", "10.0.1.50", "172.16.4.12"]
    failed_users = ["root", "ubuntu", "admin", "deploy", "postgres"]
    invalid_users = ["oracle", "ftp", "git", "backup", "nagios", "support"]
    successful_users = ["root", "deploy", "ubuntu"]
    fingerprints = [
        "ED25519 SHA256:g8vRVSevTl39e4q18Hwf8kxyLJ8l0E2Y8nZ3x4Q5p6Q",
        "ED25519 SHA256:Wv74R0M5gJ2X2vP7k1Yv8bL3n4A6s9d2f7q0c3m8n1E",
        "RSA SHA256:6fP9wV4kT3bN2cQ8xD7mJ1hL5sZ0aE4rY9uI3oP6qW",
    ]

    entries: list[tuple[datetime, str]] = []
    first_day = (datetime.utcnow() - timedelta(days=30)).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )

    for day_offset in range(30):
        day_start = first_day + timedelta(days=day_offset)
        event_count = rng.randint(8, 13)

        for _ in range(event_count):
            ts = day_start + timedelta(
                hours=rng.randint(0, 23),
                minutes=rng.randint(0, 59),
                seconds=rng.randint(0, 59),
            )
            pid = rng.randint(1200, 65000)
            port = rng.randint(32000, 65535)

            if rng.random() < 0.74:
                source = rng.choice(attacker_ips)
                event_type = rng.choice(("failed", "invalid", "closed"))
                if event_type == "failed":
                    user = rng.choice(failed_users)
                    msg = f"sshd[{pid}]: Failed password for {user} from {source} port {port} ssh2"
                elif event_type == "invalid":
                    user = rng.choice(invalid_users)
                    msg = f"sshd[{pid}]: Invalid user {user} from {source} port {port}"
                else:
                    user = rng.choice(failed_users)
                    msg = (
                        f"sshd[{pid}]: Connection closed by authenticating user "
                        f"{user} {source} port {port} [preauth]"
                    )
            else:
                source = rng.choice(internal_ips)
                user = rng.choice(successful_users)
                if rng.random() < 0.55:
                    fp = rng.choice(fingerprints)
                    msg = f"sshd[{pid}]: Accepted publickey for {user} from {source} port {port} ssh2: {fp}"
                else:
                    msg = f"sshd[{pid}]: Accepted password for {user} from {source} port {port} ssh2"

            entries.append((ts, msg))

        # Guarantee at least one successful login and session-open event per day.
        ts = day_start + timedelta(hours=rng.randint(6, 22), minutes=rng.randint(0, 59))
        pid = rng.randint(1200, 65000)
        port = rng.randint(32000, 65535)
        user = rng.choice(successful_users)
        source = rng.choice(internal_ips)
        fp = rng.choice(fingerprints)
        entries.append(
            (ts, f"sshd[{pid}]: Accepted publickey for {user} from {source} port {port} ssh2: {fp}")
        )
        entries.append(
            (
                ts + timedelta(seconds=2),
                f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=0) by (uid=0)",
            )
        )

    lines = [
        f"{_fmt_syslog_time(ts)} {HOSTNAME} {msg}"
        for ts, msg in sorted(entries, key=lambda item: item[0])
    ]
    return "\n".join(lines) + "\n"


def build_content_map() -> dict[str, str]:
    """Return virtual-path to file-content mapping."""
    return {
        "/root/.bash_history": generate_bash_history(),
        "/root/.ssh/authorized_keys": AUTHORIZED_KEYS,
        "/etc/os-release": OS_RELEASE,
        "/etc/hostname": f"{HOSTNAME}\n",
        "/etc/hosts": HOSTS_FILE,
        "/var/www/html/index.php": INDEX_PHP,
        "/var/www/html/.env": ENV_FILE,
        "/var/log/auth.log": generate_auth_log(),
        "/opt/app/config.yml": APP_CONFIG,
        "/opt/scripts/deploy.sh": DEPLOY_SH,
    }


def validate_environment() -> None:
    """Validate critical Cowrie paths before any write/register action."""
    if not FSCTL.exists():
        raise FileNotFoundError(f"fsctl not found: {FSCTL}")
    if not PICKLE.exists():
        raise FileNotFoundError(f"fs.pickle not found: {PICKLE}")
    HONEYFS_ROOT.mkdir(parents=True, exist_ok=True)


def write_honeyfs_file(
    virtual_path: str,
    content: str,
    ensured_dirs: set[str],
    written_files: list[tuple[str, int]],
) -> None:
    """Write a single honeyfs file for a virtual path like /etc/hosts."""
    rel_path = virtual_path.lstrip("/")
    destination = HONEYFS_ROOT / rel_path
    destination.parent.mkdir(parents=True, exist_ok=True)

    current = destination.parent
    while current != HONEYFS_ROOT and current != current.parent:
        ensured_dirs.add("/" + str(current.relative_to(HONEYFS_ROOT)))
        current = current.parent

    destination.write_text(content, encoding="utf-8")
    if destination.as_posix().endswith("/opt/scripts/deploy.sh"):
        destination.chmod(0o755)

    written_files.append((virtual_path, len(content.encode("utf-8"))))


def sort_virtual_paths(paths: set[str]) -> list[str]:
    """Sort by depth then lexicographically for deterministic fsctl order."""
    return sorted(paths, key=lambda p: (len(PurePosixPath(p).parts), p))


def collect_registration_paths(content_paths: list[str]) -> tuple[set[str], set[str]]:
    """Build directory/file path sets that should exist in Cowrie's pickle."""
    dir_paths = set(STANDARD_DIRS)
    file_paths = set(content_paths)
    file_paths.add("/root/.bash_history")

    for file_path in file_paths:
        parent = PurePosixPath(file_path).parent
        while str(parent) not in ("", ".", "/"):
            dir_paths.add(str(parent))
            parent = parent.parent

    return dir_paths, file_paths


def run_fsctl(command: str, target: str) -> str | None:
    """Run one fsctl command. Returns warning message, or None on success."""
    try:
        result = subprocess.run(
            [str(FSCTL), str(PICKLE), command, target],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive runtime handling
        return f"{command} {target}: {exc}"

    combined_output = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode != 0 and "already exists" not in combined_output:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return f"{command} {target}: {detail}"

    return None


def register_virtual_paths(dir_paths: set[str], file_paths: set[str]) -> list[str]:
    """Register directories then files in pickle via fsctl."""
    warnings: list[str] = []

    for directory in sort_virtual_paths(dir_paths):
        warning = run_fsctl("mkdir", directory)
        if warning:
            warnings.append(warning)

    for file_path in sort_virtual_paths(file_paths):
        warning = run_fsctl("touch", file_path)
        if warning:
            warnings.append(warning)

    return warnings


def print_summary(
    ensured_dirs: set[str],
    written_files: list[tuple[str, int]],
    registered_dirs: set[str],
    registered_files: set[str],
    warnings: list[str],
) -> None:
    """Print final summary of all work done by this script."""
    print("\nSummary")
    print("=" * 72)
    print(f"Honeyfs root: {HONEYFS_ROOT}")
    print(f"fsctl path:    {FSCTL}")
    print(f"pickle path:   {PICKLE}")

    print(f"\nHoneyfs directories ensured: {len(ensured_dirs)}")
    for path in sorted(ensured_dirs):
        print(f"  - {path}")

    print(f"\nHoneyfs files written: {len(written_files)}")
    for path, size in written_files:
        print(f"  - {path} ({size} bytes)")

    print(f"\nVirtual directories registered: {len(registered_dirs)}")
    for path in sort_virtual_paths(registered_dirs):
        print(f"  - {path}")

    print(f"\nVirtual files registered: {len(registered_files)}")
    for path in sort_virtual_paths(registered_files):
        print(f"  - {path}")

    if warnings:
        print(f"\nfsctl warnings: {len(warnings)}")
        for warning in warnings:
            print(f"  - {warning}")
    else:
        print("\nfsctl warnings: none")

    print("\nDone. The Cowrie shell should now look like an Ubuntu 22.04 web server.")


def main() -> int:
    print("MORPH honeyfs setup")
    print("=" * 72)

    try:
        validate_environment()
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    content_map = build_content_map()

    ensured_dirs: set[str] = set()
    written_files: list[tuple[str, int]] = []
    print("\nWriting honeyfs bait files...")
    for virtual_path, content in content_map.items():
        write_honeyfs_file(virtual_path, content, ensured_dirs, written_files)
        print(f"  wrote {virtual_path}")

    registered_dirs, registered_files = collect_registration_paths(list(content_map.keys()))

    print("\nRegistering virtual filesystem paths via fsctl...")
    warnings = register_virtual_paths(registered_dirs, registered_files)

    print_summary(
        ensured_dirs,
        written_files,
        registered_dirs,
        registered_files,
        warnings,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
