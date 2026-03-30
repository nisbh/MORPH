#!/usr/bin/env python3
"""
MORPH - Deception Module

Creates fake static assets and adapts honeypot environment based on attacker behavior.
"""

import os
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Any

# Base paths
FAKE_ASSETS_DIR = os.getenv("FAKE_ASSETS_DIR", "/home/nb/cowrie/fake_assets")
FAKE_FS_DIR = os.getenv("FAKE_FS_DIR", "/home/nb/cowrie/fake_fs")
LOG_FILE = os.getenv("DECEPTION_LOG", "morph/deception.log")

# Fake content templates
FAKE_DB_BACKUP = """-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
-- Host: localhost    Database: production_db
-- Server version: 8.0.32-0ubuntu0.22.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('admin','user','moderator') DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=156 DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` VALUES 
(1,'admin','admin@internal.corp','$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.qVQH1Qj5Ue5J3K','admin','2023-01-15 08:30:00','2024-03-15 14:22:33'),
(2,'jsmith','john.smith@internal.corp','$2b$12$9Xn8VqBLMJHGkP5YtR2aWeZF8vN3pQ7dC1xH4mJ6fKs2bT5yU9wEi','user','2023-02-20 10:15:00','2024-03-14 09:45:12'),
(3,'mwilson','mary.wilson@internal.corp','$2b$12$KpL5mN7qR2tU8vW3xY4zAeBfC9dG6hJ1kM2nP4sT7uV0wX5yZ8aB','moderator','2023-03-10 14:00:00','2024-03-15 11:30:45'),
(4,'dbrown','david.brown@internal.corp','$2b$12$2bT5yU9wEiKpL5mN7qR2tU8vW3xY4zAeBfC9dG6hJ1kM2nP4sT7u','user','2023-04-05 09:30:00','2024-03-13 16:20:18'),
(5,'svc_backup','backup@system.local','$2b$12$BackupServiceAccountHash1234567890abcdefghijklmnopqrstuv','admin','2023-01-01 00:00:00','2024-03-15 02:00:00');

--
-- Table structure for table `api_tokens`
--

DROP TABLE IF EXISTS `api_tokens`;
CREATE TABLE `api_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `token` varchar(64) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `api_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `api_tokens` VALUES
(1,1,'tk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6','Production API','2025-12-31 23:59:59'),
(2,5,'tk_backup_z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4','Backup service','2024-12-31 23:59:59');

-- Dump completed on 2024-03-15 03:00:01
"""

FAKE_API_KEYS = """# API Keys - Internal Use Only
# Last updated: 2024-03-15
# Contact: devops@internal.corp

# AWS Credentials (Production)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

# AWS Credentials (Staging)
AWS_STAGING_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE
AWS_STAGING_SECRET_ACCESS_KEY=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY

# Stripe API Keys
STRIPE_PUBLISHABLE_KEY=pk_live_51HG8k2CjEXAMPLEKEY1234567890abcdefghijk
STRIPE_SECRET_KEY=sk_live_51HG8k2CjEXAMPLEKEY0987654321zyxwvutsrqp
STRIPE_WEBHOOK_SECRET=whsec_EXAMPLEKEY1234567890abcdefghijklmnopqrs

# GitHub Personal Access Token
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_WEBHOOK_SECRET=github_webhook_secret_example_12345

# Slack Bot Token
SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx
SLACK_SIGNING_SECRET=1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p

# SendGrid API Key
SENDGRID_API_KEY=SG.XXXXXXXXXXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

# Twilio Credentials
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here_example_1234

# Database connection string (backup)
DATABASE_URL=postgresql://admin:Pr0d_P@ssw0rd_2024!@db.internal.corp:5432/production

# Redis
REDIS_URL=redis://:R3d1s_S3cr3t_K3y@cache.internal.corp:6379/0
"""

FAKE_ENV = """# Production Environment Configuration
# DO NOT COMMIT TO VERSION CONTROL

# Application
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:Xk5jM2Nz8pQr7tYv9wBdFgHjKmNpRsTvXyZ1234567=
APP_URL=https://app.internal.corp

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=db-primary.internal.corp
DB_PORT=3306
DB_DATABASE=production_app
DB_USERNAME=app_prod_user
DB_PASSWORD=Pr0d_DB_P@ss_2024!SecureXyz

# Database Replica (Read-Only)
DB_REPLICA_HOST=db-replica.internal.corp
DB_REPLICA_USERNAME=app_readonly
DB_REPLICA_PASSWORD=R3ad0nly_P@ss_2024!

# Redis Cache
REDIS_HOST=cache.internal.corp
REDIS_PASSWORD=R3d1s_C@ch3_P@ss!
REDIS_PORT=6379

# Session & Queue
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
CACHE_DRIVER=redis

# Mail Configuration
MAIL_MAILER=smtp
MAIL_HOST=smtp.internal.corp
MAIL_PORT=587
MAIL_USERNAME=noreply@internal.corp
MAIL_PASSWORD=M@1l_Srv_P@ss_2024!
MAIL_ENCRYPTION=tls

# AWS S3 Storage
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=internal-corp-prod-assets

# JWT Secret
JWT_SECRET=jwt_super_secret_key_2024_do_not_share_with_anyone_ever

# Internal API Keys
INTERNAL_API_KEY=int_api_k3y_s3cr3t_pr0d_2024
ADMIN_API_SECRET=adm1n_@p1_s3cr3t_k3y_xyz789
"""

FAKE_README_RECON = """# Internal Documentation

## Directory Structure

This server contains sensitive internal resources. Please ensure you have proper authorization.

### Important Directories:
- `/var/backups/` - Daily database backups (encrypted)
- `/opt/secrets/` - Service account credentials
- `/home/admin/.ssh/` - SSH keys for deployment
- `/etc/app/config/` - Application configuration files

### Quick Links:
- Admin Panel: https://admin.internal.corp (requires VPN)
- API Docs: https://api-docs.internal.corp/v2
- Monitoring: https://grafana.internal.corp

## Contact
For access requests, contact: security@internal.corp
"""


def _log(message: str) -> None:
    """Log a message to the deception log file."""
    log_path = Path(LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry)


def _generate_random_string(length: int = 16) -> str:
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def _generate_fake_credentials() -> str:
    """Generate a fake credentials file content."""
    fake_user = random.choice(["svc_deploy", "backup_admin", "jenkins_user", "ansible_svc", "terraform_svc"])
    fake_pass = _generate_random_string(20)
    fake_host = random.choice(["db-master", "db-slave", "cache-01", "app-server", "jump-host"])
    
    return f"""# Service Account Credentials
# Auto-generated - DO NOT MODIFY

[{fake_host}.internal.corp]
username = {fake_user}
password = {fake_pass}
port = {random.choice([22, 3306, 5432, 6379, 27017])}

# SSH Key Path (if applicable)
key_file = /opt/keys/{fake_user}_rsa

# Last rotated: {datetime.now().strftime("%Y-%m-%d")}
# Next rotation: {datetime.now().strftime("%Y")}-12-31
"""


def create_static_assets() -> None:
    """Create the initial set of fake static assets."""
    assets_dir = Path(FAKE_ASSETS_DIR)
    assets_dir.mkdir(parents=True, exist_ok=True)
    
    # Create fake SQL dump
    sql_path = assets_dir / "db_backup.sql"
    sql_path.write_text(FAKE_DB_BACKUP, encoding="utf-8")
    _log(f"Created fake SQL dump: {sql_path}")
    
    # Create fake API keys file
    api_path = assets_dir / "api_keys.txt"
    api_path.write_text(FAKE_API_KEYS, encoding="utf-8")
    _log(f"Created fake API keys: {api_path}")
    
    # Create fake .env file
    env_path = assets_dir / ".env"
    env_path.write_text(FAKE_ENV, encoding="utf-8")
    _log(f"Created fake .env: {env_path}")


def create_fake_directories() -> None:
    """Create the fake directory structure."""
    directories = [
        Path(FAKE_FS_DIR) / "internal",
        Path(FAKE_FS_DIR) / "finance",
        Path(FAKE_FS_DIR) / "admin",
    ]
    
    for dir_path in directories:
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # Add a placeholder file to make directories look used
        placeholder = dir_path / ".gitkeep"
        placeholder.touch()
        
        _log(f"Created fake directory: {dir_path}")


def adapt(session: dict[str, Any], classification: dict[str, Any]) -> list[str]:
    """
    Adapt the honeypot environment based on session behavior.

    Args:
        session: Session dict from the parser
        classification: Classification dict with type, intent, risk, matched_rules

    Returns:
        List of actions taken
    """
    actions: list[str] = []
    risk = classification.get("risk", "low")
    intent = classification.get("intent", "recon")
    session_id = session.get("session_id", "unknown")

    _log(f"Adapting for session {session_id}: risk={risk}, intent={intent}")

    # High risk: plant fake credentials in a random subdirectory
    if risk == "high":
        random_subdir = _generate_random_string(8).lower()
        creds_dir = Path(FAKE_FS_DIR) / "internal" / random_subdir
        creds_dir.mkdir(parents=True, exist_ok=True)
        
        creds_file = creds_dir / "credentials.conf"
        creds_file.write_text(_generate_fake_credentials(), encoding="utf-8")
        
        action = f"Planted fake credentials at {creds_file}"
        _log(action)
        actions.append(action)

    # Recon intent: add README hinting at sensitive directories
    if intent == "recon":
        readme_locations = [
            Path(FAKE_FS_DIR) / "internal" / "README.md",
            Path(FAKE_FS_DIR) / "admin" / "README.md",
        ]
        
        for readme_path in readme_locations:
            if not readme_path.exists():
                readme_path.parent.mkdir(parents=True, exist_ok=True)
                readme_path.write_text(FAKE_README_RECON, encoding="utf-8")
                
                action = f"Created recon bait README at {readme_path}"
                _log(action)
                actions.append(action)

    if not actions:
        _log(f"No adaptation needed for session {session_id}")
        actions.append("No adaptation actions taken")

    return actions


def initialize() -> None:
    """Initialize the deception environment."""
    _log("Initializing MORPH deception module")
    create_static_assets()
    create_fake_directories()
    _log("Deception environment initialized")


if __name__ == "__main__":
    print("MORPH Deception Module")
    print("=" * 60)
    
    # Initialize the deception environment
    print("\nInitializing deception assets...")
    initialize()
    print(f"Created static assets in {FAKE_ASSETS_DIR}")
    print(f"Created fake directories in {FAKE_FS_DIR}")
    
    # Demo adapt function
    print("\nTesting adapt() function...")
    
    test_session = {
        "session_id": "test_session_001",
        "commands": ["ls", "cat /etc/passwd"],
    }
    
    test_classifications = [
        {"risk": "high", "intent": "exploit", "type": "bot"},
        {"risk": "medium", "intent": "recon", "type": "human"},
        {"risk": "low", "intent": "recon", "type": "human"},
    ]
    
    for classification in test_classifications:
        print(f"\nClassification: {classification}")
        actions = adapt(test_session, classification)
        for action in actions:
            print(f"  → {action}")
    
    print(f"\nLog file: {LOG_FILE}")
    print("Done.")
