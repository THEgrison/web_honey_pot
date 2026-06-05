import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "data" / "honeypot.db"))

    DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
    DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "change-me")

    # ip_anonymization_mode: none|truncate|hash
    IP_ANONYMIZATION_MODE = os.environ.get("IP_ANONYMIZATION_MODE", "hash")
    IP_HASH_SALT = os.environ.get("IP_HASH_SALT", "honeypot-salt")

    MAX_DB_REQUEST_ROWS = int(os.environ.get("MAX_DB_REQUEST_ROWS", "500000"))
    LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
    LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

    RANDOM_NETWORK_PAGES = int(os.environ.get("RANDOM_NETWORK_PAGES", "30"))
    RANDOM_NETWORK_LINKS_PER_PAGE = int(os.environ.get("RANDOM_NETWORK_LINKS_PER_PAGE", "4"))

    EXPORT_DIR = str(BASE_DIR / "exports")
    REPORT_DIR = str(BASE_DIR / "reports")

    FP_DEPTH_TARGET = int(os.environ.get("FP_DEPTH_TARGET", "20"))
    FP_COVERAGE_TARGET = int(os.environ.get("FP_COVERAGE_TARGET", "30"))
    FP_SPEED_FAST_RPM = int(os.environ.get("FP_SPEED_FAST_RPM", "80"))
    FP_DEPTH_FIRST_MIN_DEPTH = int(os.environ.get("FP_DEPTH_FIRST_MIN_DEPTH", "12"))
    FP_BREADTH_MIN_UNIQUE_PAGES = int(os.environ.get("FP_BREADTH_MIN_UNIQUE_PAGES", "25"))
    FP_BREADTH_MAX_DEPTH = int(os.environ.get("FP_BREADTH_MAX_DEPTH", "8"))
    FP_ITERATIVE_REVISIT_THRESHOLD = float(os.environ.get("FP_ITERATIVE_REVISIT_THRESHOLD", "0.35"))
    FP_REVISIT_TARGET = float(os.environ.get("FP_REVISIT_TARGET", "0.15"))
    FP_REVISIT_SENSITIVITY = float(os.environ.get("FP_REVISIT_SENSITIVITY", "40"))

    FP_PACE_GOOD_MIN_SEC = float(os.environ.get("FP_PACE_GOOD_MIN_SEC", "0.5"))
    FP_PACE_GOOD_MAX_SEC = float(os.environ.get("FP_PACE_GOOD_MAX_SEC", "8.0"))

    FP_WEIGHT_DEPTH = float(os.environ.get("FP_WEIGHT_DEPTH", "20"))
    FP_WEIGHT_COVERAGE = float(os.environ.get("FP_WEIGHT_COVERAGE", "20"))
    FP_WEIGHT_CONSULT_ROBOTS = float(os.environ.get("FP_WEIGHT_CONSULT_ROBOTS", "10"))
    FP_WEIGHT_RESPECT_ROBOTS = float(os.environ.get("FP_WEIGHT_RESPECT_ROBOTS", "10"))
    FP_WEIGHT_CONSULT_SITEMAP = float(os.environ.get("FP_WEIGHT_CONSULT_SITEMAP", "5"))
    FP_WEIGHT_JS_CAPABLE = float(os.environ.get("FP_WEIGHT_JS_CAPABLE", "20"))
    FP_WEIGHT_COOKIES_CAPABLE = float(os.environ.get("FP_WEIGHT_COOKIES_CAPABLE", "10"))
    FP_WEIGHT_PACE_GOOD = float(os.environ.get("FP_WEIGHT_PACE_GOOD", "15"))
    FP_WEIGHT_PACE_TOO_FAST = float(os.environ.get("FP_WEIGHT_PACE_TOO_FAST", "5"))
    FP_WEIGHT_PACE_SLOW = float(os.environ.get("FP_WEIGHT_PACE_SLOW", "10"))
    FP_WEIGHT_PACE_NEUTRAL = float(os.environ.get("FP_WEIGHT_PACE_NEUTRAL", "8"))
    FP_WEIGHT_REVISIT = float(os.environ.get("FP_WEIGHT_REVISIT", "10"))

    STORE_RAW_IP = os.environ.get("STORE_RAW_IP", "false").lower() in {"1", "true", "yes"}
    ALLOW_RAW_IP_EXPORT = os.environ.get("ALLOW_RAW_IP_EXPORT", "false").lower() in {
        "1",
        "true",
        "yes",
    }

    SESSION_IDLE_SECONDS = int(os.environ.get("SESSION_IDLE_SECONDS", "1800"))
    KPI_DEFAULT_WINDOW_DAYS = int(os.environ.get("KPI_DEFAULT_WINDOW_DAYS", "30"))

    ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
    ALERT_SPIKE_MULTIPLIER = float(os.environ.get("ALERT_SPIKE_MULTIPLIER", "2.5"))
    ALERT_MIN_BOT_HITS_PER_HOUR = int(os.environ.get("ALERT_MIN_BOT_HITS_PER_HOUR", "120"))
    ALERT_SUSPICIOUS_HITS_PER_HOUR = int(os.environ.get("ALERT_SUSPICIOUS_HITS_PER_HOUR", "25"))
