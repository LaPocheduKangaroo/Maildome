"""
config.py — loads and validates mailshield.conf

Every other module imports settings from here.
Nothing reads the config file directly except this module.
"""

import configparser
import os
import sys
from dataclasses import dataclass
from pathlib import Path


CONFIG_PATH = os.environ.get(
    "MAILSHIELD_CONFIG",
    "/etc/mailshield/mailshield.conf"
)


@dataclass
class AcquisitionConfig:
    mode: str
    imap_host: str
    imap_port: int
    imap_use_ssl: bool
    imap_user: str
    imap_password: str
    imap_mailbox: str
    imap_idle: bool
    imap_poll_interval: int
    dedup_window_hours: int
    storage_path: Path


@dataclass
class ScoringConfig:
    threshold_suspicious: int
    threshold_dangerous: int
    weight_spf_dkim_dmarc: int
    weight_ip_reputation: int
    weight_url_blacklist: int
    weight_header_anomalies: int
    weight_typosquatting: int


@dataclass
class NotificationsConfig:
    admin_email: str
    degraded_alert: bool
    dangerous_alert: bool


@dataclass
class ApiConfig:
    host: str
    port: int
    token_expire_minutes: int


@dataclass
class LoggingConfig:
    level: str
    path: Path


@dataclass
class Settings:
    acquisition: AcquisitionConfig
    scoring: ScoringConfig
    notifications: NotificationsConfig
    api: ApiConfig
    logging: LoggingConfig
    groups: dict          # group_name → profile
    default_profile: str
    blacklists: dict      # list_name → enabled (bool)


def load(path: str = CONFIG_PATH) -> Settings:
    """
    Load and validate configuration from file.
    Exits with a clear error message if required values are missing.
    """
    if not Path(path).exists():
        print(f"error: config file not found: {path}", file=sys.stderr)
        print(f"  copy core/config/mailshield.conf to {path} and edit it.", file=sys.stderr)
        sys.exit(1)

    c = configparser.ConfigParser()
    c.read(path)

    # IMAP password comes from environment, not config file
    imap_password = os.environ.get("IMAP_PASSWORD", "")

    try:
        acquisition = AcquisitionConfig(
            mode=c.get("acquisition", "mode"),
            imap_host=c.get("acquisition", "imap_host"),
            imap_port=c.getint("acquisition", "imap_port"),
            imap_use_ssl=c.getboolean("acquisition", "imap_use_ssl"),
            imap_user=c.get("acquisition", "imap_user"),
            imap_password=imap_password,
            imap_mailbox=c.get("acquisition", "imap_mailbox"),
            imap_idle=c.getboolean("acquisition", "imap_idle"),
            imap_poll_interval=c.getint("acquisition", "imap_poll_interval"),
            dedup_window_hours=c.getint("acquisition", "dedup_window_hours"),
            storage_path=Path(c.get("acquisition", "storage_path")),
        )

        scoring = ScoringConfig(
            threshold_suspicious=c.getint("scoring", "threshold_suspicious"),
            threshold_dangerous=c.getint("scoring", "threshold_dangerous"),
            weight_spf_dkim_dmarc=c.getint("scoring", "weight_spf_dkim_dmarc"),
            weight_ip_reputation=c.getint("scoring", "weight_ip_reputation"),
            weight_url_blacklist=c.getint("scoring", "weight_url_blacklist"),
            weight_header_anomalies=c.getint("scoring", "weight_header_anomalies"),
            weight_typosquatting=c.getint("scoring", "weight_typosquatting"),
        )

        notifications = NotificationsConfig(
            admin_email=c.get("notifications", "admin_email", fallback=""),
            degraded_alert=c.getboolean("notifications", "degraded_alert"),
            dangerous_alert=c.getboolean("notifications", "dangerous_alert"),
        )

        api = ApiConfig(
            host=c.get("api", "host"),
            port=c.getint("api", "port"),
            token_expire_minutes=c.getint("api", "token_expire_minutes"),
        )

        logging_cfg = LoggingConfig(
            level=c.get("logging", "level"),
            path=Path(c.get("logging", "path")),
        )

        # Groups section: every key except 'default_profile' is a group mapping
        groups = {}
        default_profile = "standard"
        if c.has_section("groups"):
            for key, value in c.items("groups"):
                if key == "default_profile":
                    default_profile = value
                else:
                    groups[key] = value

        # Blacklists section
        blacklists = {}
        if c.has_section("blacklists"):
            for key, value in c.items("blacklists"):
                if not key.startswith("custom_"):
                    try:
                        blacklists[key] = c.getboolean("blacklists", key)
                    except ValueError:
                        pass  # skip custom list URLs

    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"error: missing required config value: {e}", file=sys.stderr)
        sys.exit(1)

    return Settings(
        acquisition=acquisition,
        scoring=scoring,
        notifications=notifications,
        api=api,
        logging=logging_cfg,
        groups=groups,
        default_profile=default_profile,
        blacklists=blacklists,
    )


# Module-level singleton — import this in other modules
settings = load()
