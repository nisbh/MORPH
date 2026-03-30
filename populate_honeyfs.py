#!/usr/bin/env python3
"""
populate_honeyfs.py - One-time setup to make Cowrie look like a real Ubuntu web server.

Creates realistic config files, logs, and user artifacts in honeyfs,
then registers all paths in fs.pickle using fsctl.

Run: python3 populate_honeyfs.py
"""

import os
import subprocess
import random
from datetime import datetime, timedelta

# Paths
HONEYFS_ROOT = "/home/nb/cowrie/honeyfs"
FSCTL = "/home/nb/cowrie/cowrie-env/bin/fsctl"
PICKLE = "/home/nb/cowrie/src/cowrie/data/fs.pickle"

# Track created files for summary
created_files = []
created_dirs = []


def ensure_dir(rel_path):
    """Create directory in honeyfs if it doesn't exist."""
    full_path = os.path.join(HONEYFS_ROOT, rel_path)
    if not os.path.exists(full_path):
        os.makedirs(full_path, exist_ok=True)
        created_dirs.append(rel_path)
    return full_path


def write_file(rel_path, content):
    """Write a file to honeyfs."""
    # Ensure parent directory exists
    parent = os.path.dirname(rel_path)
    if parent:
        ensure_dir(parent)
    
    full_path = os.path.join(HONEYFS_ROOT, rel_path)
    with open(full_path, 'w') as f:
        f.write(content)
    created_files.append(rel_path)
    print(f"  Created: /{rel_path}")


def register_in_pickle(rel_path, is_dir=False):
    """Register a path in fs.pickle using fsctl."""
    virt_path = "/" + rel_path
    cmd = "mkdir" if is_dir else "touch"
    
    try:
        result = subprocess.run(
            [FSCTL, PICKLE, cmd, virt_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0 and "already exists" not in result.stderr.lower():
            print(f"  Warning: fsctl {cmd} {virt_path}: {result.stderr.strip()}")
    except Exception as e:
        print(f"  Warning: fsctl failed for {virt_path}: {e}")


# ============================================================================
# FILE CONTENTS
# ============================================================================

NGINX_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""

MYSQL_CNF = """[mysqld]
user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
lc-messages-dir = /usr/share/mysql

bind-address    = 127.0.0.1
mysqlx-bind-address = 127.0.0.1

key_buffer_size         = 16M
max_allowed_packet      = 64M
thread_stack            = 256K
thread_cache_size       = 8
max_connections         = 100

query_cache_limit       = 1M
query_cache_size        = 16M

log_error = /var/log/mysql/error.log
slow_query_log          = 1
slow_query_log_file     = /var/log/mysql/mysql-slow.log
long_query_time         = 2

[mysqldump]
quick
quote-names
max_allowed_packet      = 16M
"""

CRONTAB = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

# Database backups
0 2     * * *   root    /opt/scripts/backup.sh >> /var/log/backup.log 2>&1
0 3     * * 0   root    /opt/scripts/weekly_maintenance.sh

# Log rotation
0 0     * * *   root    /usr/sbin/logrotate /etc/logrotate.conf

# SSL cert renewal
0 4     * * *   root    certbot renew --quiet
"""


def generate_auth_log():
    """Generate fake SSH auth log with login attempts."""
    lines = []
    base_time = datetime.now() - timedelta(days=7)
    
    events = [
        ("sshd[{pid}]: Accepted publickey for deploy from 10.0.1.50 port {port} ssh2", True),
        ("sshd[{pid}]: Failed password for invalid user admin from 185.220.101.{oct} port {port} ssh2", False),
        ("sshd[{pid}]: Failed password for root from 45.133.1.{oct} port {port} ssh2", False),
        ("sshd[{pid}]: Accepted password for deploy from 10.0.1.50 port {port} ssh2", True),
        ("sshd[{pid}]: Connection closed by authenticating user root 91.240.118.{oct} port {port} [preauth]", False),
        ("sshd[{pid}]: Invalid user oracle from 193.42.33.{oct} port {port}", False),
        ("sshd[{pid}]: Failed password for invalid user test from 178.128.{oct2}.{oct} port {port} ssh2", False),
        ("sshd[{pid}]: Accepted publickey for root from 10.0.1.1 port {port} ssh2", True),
        ("sshd[{pid}]: pam_unix(sshd:session): session opened for user deploy(uid=1000) by (uid=0)", True),
        ("sshd[{pid}]: Disconnecting invalid user admin 185.220.101.{oct} port {port}: Too many authentication failures", False),
    ]
    
    for i in range(50):
        event_time = base_time + timedelta(hours=random.randint(0, 168))
        month_day = event_time.strftime("%b %d")
        time_str = event_time.strftime("%H:%M:%S")
        
        template, _ = random.choice(events)
        msg = template.format(
            pid=random.randint(10000, 65000),
            port=random.randint(40000, 60000),
            oct=random.randint(1, 254),
            oct2=random.randint(1, 254)
        )
        lines.append(f"{month_day} {time_str} web-prod-01 {msg}")
    
    lines.sort()
    return "\n".join(lines[-30:]) + "\n"


def generate_nginx_access_log():
    """Generate fake nginx access log."""
    lines = []
    base_time = datetime.now() - timedelta(days=3)
    
    paths = [
        ("GET", "/", 200, 4521),
        ("GET", "/api/v1/users", 200, 1823),
        ("POST", "/api/v1/login", 200, 342),
        ("GET", "/static/js/app.js", 200, 125432),
        ("GET", "/static/css/main.css", 200, 34521),
        ("GET", "/favicon.ico", 200, 1150),
        ("GET", "/api/v1/products", 200, 8932),
        ("GET", "/health", 200, 15),
        ("POST", "/api/v1/orders", 201, 523),
        ("GET", "/robots.txt", 200, 143),
        ("GET", "/.env", 404, 162),
        ("GET", "/wp-admin/", 404, 162),
        ("GET", "/phpmyadmin/", 404, 162),
        ("POST", "/api/v1/login", 401, 89),
        ("GET", "/api/v1/admin/users", 403, 64),
    ]
    
    ips = [
        "10.0.1.50", "10.0.1.51", "10.0.1.52",
        "192.168.1.100", "172.16.0.15",
        "45.33.32.156", "104.21.54.163",
        "185.220.101.42", "91.240.118.73"
    ]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "curl/7.81.0",
        "python-requests/2.28.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]
    
    for i in range(100):
        event_time = base_time + timedelta(minutes=random.randint(0, 4320))
        time_str = event_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        ip = random.choice(ips)
        method, path, status, size = random.choice(paths)
        ua = random.choice(user_agents)
        
        lines.append(f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')
    
    lines.sort()
    return "\n".join(lines[-50:]) + "\n"


def generate_syslog():
    """Generate fake syslog entries."""
    lines = []
    base_time = datetime.now() - timedelta(days=1)
    
    entries = [
        "systemd[1]: Started Daily apt download activities.",
        "systemd[1]: Starting Daily Cleanup of Temporary Directories...",
        "systemd[1]: Finished Daily Cleanup of Temporary Directories.",
        "systemd[1]: Starting Rotate log files...",
        "systemd[1]: logrotate.service: Succeeded.",
        "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=185.220.101.42 DST=10.0.1.100 PROTO=TCP DPT=22",
        "CRON[12345]: (root) CMD (/opt/scripts/backup.sh >> /var/log/backup.log 2>&1)",
        "systemd[1]: Starting MySQL Community Server...",
        "mysqld[8432]: ready for connections. Version: '8.0.35'  socket: '/var/run/mysqld/mysqld.sock'",
        "nginx[1234]: nginx/1.18.0",
        "systemd[1]: Started A high performance web server and a reverse proxy server.",
        "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=91.240.118.73 DST=10.0.1.100 PROTO=TCP DPT=3306",
        "certbot[5678]: Certificate not due for renewal",
    ]
    
    for i in range(40):
        event_time = base_time + timedelta(minutes=random.randint(0, 1440))
        month_day = event_time.strftime("%b %d")
        time_str = event_time.strftime("%H:%M:%S")
        
        entry = random.choice(entries)
        lines.append(f"{month_day} {time_str} web-prod-01 {entry}")
    
    lines.sort()
    return "\n".join(lines) + "\n"


ROOT_BASH_HISTORY = """apt update
apt upgrade -y
systemctl status nginx
systemctl restart nginx
tail -f /var/log/nginx/access.log
mysql -u root -p
cd /var/www/html
ls -la
vim /etc/nginx/sites-available/default
nginx -t
systemctl reload nginx
certbot certonly --nginx -d example.com
df -h
free -m
htop
cat /var/log/auth.log | grep Failed
ufw status
netstat -tulpn
ps aux | grep mysql
docker ps
cd /opt/scripts
./backup.sh
tail -100 /var/log/backup.log
crontab -l
vim /etc/crontab
systemctl status mysql
mysqldump -u root -p webapp > /tmp/backup.sql
scp /tmp/backup.sql deploy@backup-server:/backups/
history
"""

ROOT_SSH_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vH8K9Z5U1N3G5r+kR1XqY9Zv8xvH+L9nJ8B6F3vL9Z5U1N3G5r+kR1XqY9Zv8xvH+L9nJ8B6F3vL9Z5U1N3G5r+kR1XqY9Zv8xvH+L9nJ8B6F3vLABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH ops-automation@internal.example.com
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDExample123456789ExampleKeyDataHereForDemoP+LongKeyStringContinuesHereWithMoreRandomCharsABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789== admin@jumpbox.internal
"""

DEPLOY_APP_ENV = """# Application Environment Configuration
# DO NOT COMMIT TO VERSION CONTROL

APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:K8j2L9fNq3xR5vB7mC1pW4yZ6tA8sE0hU2iO4nM3kJ6=

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=webapp_production
DB_USERNAME=webapp_user
DB_PASSWORD=Pr0d_DB_P@ssw0rd_2024!

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=R3d1s_S3cr3t_K3y
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@mg.example.com
MAIL_PASSWORD=mg_api_key_1234567890abcdef

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=webapp-assets-prod

STRIPE_KEY=pk_live_1234567890abcdefghijklmnop
STRIPE_SECRET=sk_live_abcdefghijklmnop1234567890
"""


def main():
    print("=" * 60)
    print("MORPH Honeyfs Population Script")
    print("=" * 60)
    print(f"\nTarget: {HONEYFS_ROOT}")
    print(f"Pickle: {PICKLE}")
    print()
    
    # Create all the files
    print("Creating files...\n")
    
    write_file("etc/nginx/nginx.conf", NGINX_CONF)
    write_file("etc/mysql/my.cnf", MYSQL_CNF)
    write_file("etc/crontab", CRONTAB)
    write_file("var/log/auth.log", generate_auth_log())
    write_file("var/log/nginx/access.log", generate_nginx_access_log())
    write_file("var/log/syslog", generate_syslog())
    write_file("root/.bash_history", ROOT_BASH_HISTORY)
    write_file("root/.ssh/authorized_keys", ROOT_SSH_KEY)
    write_file("home/deploy/app.env", DEPLOY_APP_ENV)
    
    # Also create some directories that attackers might explore
    ensure_dir("var/lib/mysql")
    ensure_dir("var/www/html")
    ensure_dir("opt/scripts")
    ensure_dir("opt/backup")
    
    print("\n" + "-" * 60)
    print("Registering paths in fs.pickle...")
    print()
    
    # Register directories first
    all_dirs = set()
    for f in created_files:
        parts = f.split('/')
        for i in range(1, len(parts)):
            all_dirs.add('/'.join(parts[:i]))
    
    for d in created_dirs:
        all_dirs.add(d)
    
    for d in sorted(all_dirs):
        register_in_pickle(d, is_dir=True)
        print(f"  mkdir /{d}")
    
    # Register files
    for f in created_files:
        register_in_pickle(f, is_dir=False)
        print(f"  touch /{f}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"\nFiles created: {len(created_files)}")
    print(f"Directories created: {len(created_dirs)}")
    print(f"\nTotal paths registered in pickle: {len(all_dirs) + len(created_files)}")
    print("\nThe honeypot now looks like a production Ubuntu web server with:")
    print("  - nginx web server configuration")
    print("  - MySQL database configuration")  
    print("  - System crontab with backup jobs")
    print("  - SSH auth logs with login attempts")
    print("  - nginx access logs with HTTP traffic")
    print("  - System logs (syslog)")
    print("  - Root user's command history and SSH keys")
    print("  - Deploy user's app.env with fake credentials")
    print("\nRestart Cowrie to load the updated pickle:")
    print("  sudo systemctl restart cowrie")
    print()


if __name__ == "__main__":
    main()
