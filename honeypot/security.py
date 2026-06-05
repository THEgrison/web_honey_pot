import hashlib
from functools import wraps

from flask import Response, current_app, request, session


def anonymize_ip(ip_addr):
    if not ip_addr:
        return "0.0.0.0"

    mode = current_app.config["IP_ANONYMIZATION_MODE"].lower()
    if mode == "none":
        return ip_addr
    if mode == "truncate":
        if ":" in ip_addr:
            return ":".join(ip_addr.split(":")[:4]) + "::"
        parts = ip_addr.split(".")
        return ".".join(parts[:3]) + ".0"

    salted = f"{current_app.config['IP_HASH_SALT']}::{ip_addr}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()[:24]


def make_visitor_key(ip_anonymized, user_agent):
    raw = f"{ip_anonymized}|{(user_agent or '').lower()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def check_dashboard_credentials(username, password):
    return (
        username == current_app.config["DASHBOARD_USERNAME"]
        and password == current_app.config["DASHBOARD_PASSWORD"]
    )


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("dashboard_auth"):
            return Response(status=302, headers={"Location": "/dashboard/login"})
        return view_func(*args, **kwargs)

    return wrapped


def safe_int(value, default, min_value=None, max_value=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    if min_value is not None:
        parsed = max(parsed, min_value)
    if max_value is not None:
        parsed = min(parsed, max_value)
    return parsed


def is_robot_file(path):
    return path in {"/robots.txt", "/sitemap.xml"}


def has_disallowed_marker(path):
    return "/reseau/profondeur/" in path and path.endswith("/13")
