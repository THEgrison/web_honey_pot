import csv
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import request as urlrequest

from flask import current_app

from .db import get_db, utc_now_iso


SUSPICIOUS_PATTERNS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/manager",
    "/backend",
    "/cpanel",
    "/panel",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    "/.env",
    "/cgi-bin",
    "/xmlrpc.php",
    "/shell",
]


def infer_network_scope(ip_raw):
    if not ip_raw:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_raw)
    except ValueError:
        return "invalid"

    if ip_obj.is_private:
        return "private"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_reserved:
        return "reserved"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_link_local:
        return "link_local"
    return "public"


def daily_kpi_v3(day_utc=None):
    day_utc = day_utc or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    start_iso, end_iso = _day_bounds(day_utc)
    db = get_db()

    total_hits = _scalar(
        db,
        "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND ts_utc < ?",
        (start_iso, end_iso),
    )
    bot_hits = _scalar(
        db,
        """
        SELECT COUNT(*) FROM requests
        WHERE ts_utc >= ? AND ts_utc < ? AND category != 'human_browser'
        """,
        (start_iso, end_iso),
    )

    sessions = build_sessions(start_iso=start_iso, end_iso=end_iso)
    avg_session_depth = (
        sum(s["depth_max"] for s in sessions) / len(sessions) if sessions else 0.0
    )
    avg_session_hits = (
        sum(s["hits"] for s in sessions) / len(sessions) if sessions else 0.0
    )

    suspicious_hits = _scalar(
        db,
        _suspicious_count_sql(start_iso is not None),
        _suspicious_args(start_iso, end_iso),
    )

    robots_consulted = _scalar(
        db,
        """
        SELECT COUNT(DISTINCT visitor_key) FROM requests
        WHERE ts_utc >= ? AND ts_utc < ? AND path='/robots.txt'
        """,
        (start_iso, end_iso),
    )
    robots_respected = _scalar(
        db,
        """
        SELECT COUNT(*) FROM (
            SELECT visitor_key
            FROM requests
            WHERE ts_utc >= ? AND ts_utc < ?
            GROUP BY visitor_key
            HAVING SUM(CASE WHEN path='/robots.txt' THEN 1 ELSE 0 END) > 0
               AND SUM(CASE WHEN path='/reseau/profondeur/13' THEN 1 ELSE 0 END) = 0
        )
        """,
        (start_iso, end_iso),
    )

    js_visitors = _scalar(
        db,
        """
        SELECT COUNT(DISTINCT visitor_key) FROM capability_events
        WHERE ts_utc >= ? AND ts_utc < ? AND event_name='js_executed'
        """,
        (start_iso, end_iso),
    )
    cookie_visitors = _scalar(
        db,
        """
        SELECT COUNT(DISTINCT visitor_key) FROM capability_events
        WHERE ts_utc >= ? AND ts_utc < ?
          AND event_name='cookies_supported' AND event_value='1'
        """,
        (start_iso, end_iso),
    )

    unique_visitors = _scalar(
        db,
        "SELECT COUNT(DISTINCT visitor_key) FROM requests WHERE ts_utc >= ? AND ts_utc < ?",
        (start_iso, end_iso),
    )

    scope_rows = db.execute(
        """
        SELECT COALESCE(network_scope, 'unknown') AS scope, COUNT(*) AS c
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        GROUP BY scope
        ORDER BY c DESC
        """,
        (start_iso, end_iso),
    ).fetchall()

    return {
        "day_utc": day_utc,
        "total_hits": total_hits,
        "bot_hits": bot_hits,
        "bot_hit_rate": round(bot_hits / total_hits, 4) if total_hits else 0.0,
        "session_count": len(sessions),
        "avg_session_depth": round(avg_session_depth, 2),
        "avg_session_hits": round(avg_session_hits, 2),
        "suspicious_hits": suspicious_hits,
        "robots_respect_rate": round(robots_respected / robots_consulted, 4)
        if robots_consulted
        else 0.0,
        "js_execution_rate": round(js_visitors / unique_visitors, 4) if unique_visitors else 0.0,
        "cookies_support_rate": round(cookie_visitors / unique_visitors, 4)
        if unique_visitors
        else 0.0,
        "network_scope_distribution": {row["scope"]: row["c"] for row in scope_rows},
    }


def build_sessions(start_iso=None, end_iso=None, limit=None):
    db = get_db()
    sql = """
        SELECT visitor_key, ts_utc, path, category, user_agent, ip_anonymized, COALESCE(network_scope, 'unknown') AS network_scope
        FROM requests
        WHERE 1=1
    """
    args = []
    if start_iso:
        sql += " AND ts_utc >= ?"
        args.append(start_iso)
    if end_iso:
        sql += " AND ts_utc < ?"
        args.append(end_iso)
    sql += " ORDER BY visitor_key ASC, ts_utc ASC"
    if limit is not None:
        sql += " LIMIT ?"
        args.append(int(limit))

    rows = db.execute(sql, tuple(args)).fetchall()
    idle_seconds = int(current_app.config.get("SESSION_IDLE_SECONDS", 1800))

    sessions = []
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["visitor_key"]].append(row)

    for visitor_key, items in grouped.items():
        current = []
        for row in items:
            ts = _to_dt(row["ts_utc"])
            if not current:
                current.append((ts, row))
                continue
            gap = (ts - current[-1][0]).total_seconds()
            if gap > idle_seconds:
                sessions.append(_finalize_session(visitor_key, current))
                current = [(ts, row)]
            else:
                current.append((ts, row))
        if current:
            sessions.append(_finalize_session(visitor_key, current))

    sessions.sort(key=lambda x: x["start_ts"], reverse=True)
    return sessions


def detect_drift(window_days=7, baseline_days=30):
    db = get_db()
    now = datetime.now(timezone.utc)
    recent_start = (now - timedelta(days=window_days)).isoformat()
    baseline_start = (now - timedelta(days=window_days + baseline_days)).isoformat()

    recent = _category_window_metrics(db, recent_start, now.isoformat())
    baseline = _category_window_metrics(db, baseline_start, recent_start)

    out = []
    categories = sorted(set(recent.keys()) | set(baseline.keys()))
    for category in categories:
        r = recent.get(category, {"hits": 0, "visitors": 0})
        b = baseline.get(category, {"hits": 0, "visitors": 0})
        b_hits = b["hits"] or 1
        delta_ratio = r["hits"] / b_hits
        out.append(
            {
                "category": category,
                "recent_hits": r["hits"],
                "baseline_hits": b["hits"],
                "hit_drift_ratio": round(delta_ratio, 3),
                "recent_visitors": r["visitors"],
                "baseline_visitors": b["visitors"],
            }
        )

    out.sort(key=lambda x: x["hit_drift_ratio"], reverse=True)
    return {
        "window_days": window_days,
        "baseline_days": baseline_days,
        "drift": out,
    }


def detect_anomalies(window_minutes=60):
    db = get_db()
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=window_minutes)).isoformat()
    baseline_start = (now - timedelta(hours=24)).isoformat()

    current_hits = _scalar(
        db,
        "SELECT COUNT(*) FROM requests WHERE ts_utc >= ?",
        (window_start,),
    )
    current_bot_hits = _scalar(
        db,
        "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND category != 'human_browser'",
        (window_start,),
    )
    current_suspicious = _scalar(db, _suspicious_count_sql(False), _suspicious_args(window_start, None))

    baseline_hits = _scalar(
        db,
        "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND ts_utc < ?",
        (baseline_start, window_start),
    )
    baseline_hours = max((24 * 60 - window_minutes) / 60.0, 1.0)
    baseline_hits_per_hour = baseline_hits / baseline_hours
    current_hits_per_hour = current_hits * (60.0 / max(window_minutes, 1))

    multiplier = float(current_app.config.get("ALERT_SPIKE_MULTIPLIER", 2.5))
    min_bot_hits = int(current_app.config.get("ALERT_MIN_BOT_HITS_PER_HOUR", 120))
    suspicious_threshold = int(current_app.config.get("ALERT_SUSPICIOUS_HITS_PER_HOUR", 25))

    flags = {
        "traffic_spike": current_hits_per_hour > baseline_hits_per_hour * multiplier if baseline_hits_per_hour else False,
        "bot_spike": current_bot_hits * (60.0 / max(window_minutes, 1)) > min_bot_hits,
        "suspicious_spike": current_suspicious * (60.0 / max(window_minutes, 1)) > suspicious_threshold,
    }

    return {
        "window_minutes": window_minutes,
        "current_hits": current_hits,
        "current_hits_per_hour": round(current_hits_per_hour, 2),
        "baseline_hits_per_hour": round(baseline_hits_per_hour, 2),
        "current_bot_hits": current_bot_hits,
        "current_suspicious_hits": current_suspicious,
        "flags": flags,
        "has_alert": any(flags.values()),
    }


def run_alert_pipeline(window_minutes=60):
    anomalies = detect_anomalies(window_minutes=window_minutes)
    drift = detect_drift(window_days=7, baseline_days=30)

    payload = {
        "generated_at_utc": utc_now_iso(),
        "anomalies": anomalies,
        "top_drift": drift["drift"][:5],
    }

    delivered = False
    webhook_url = (current_app.config.get("ALERT_WEBHOOK_URL") or "").strip()
    if webhook_url and anomalies.get("has_alert"):
        delivered = _post_webhook(webhook_url, payload)

    return {
        "payload": payload,
        "webhook_delivered": delivered,
        "webhook_configured": bool(webhook_url),
    }


def build_ml_dataset(limit_sessions=100000, days=60):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    sessions = build_sessions(start_iso=cutoff, limit=limit_sessions)

    dataset = []
    for s in sessions:
        feature = {
            "session_id": s["session_id"],
            "visitor_key": s["visitor_key"],
            "category": s["category"],
            "hits": s["hits"],
            "unique_pages": s["unique_pages"],
            "depth_max": s["depth_max"],
            "duration_sec": s["duration_sec"],
            "avg_gap_sec": s["avg_gap_sec"],
            "revisit_rate": s["revisit_rate"],
            "robots_seen": int(s["robots_seen"]),
            "sitemap_seen": int(s["sitemap_seen"]),
            "disallowed_seen": int(s["disallowed_seen"]),
            "network_scope": s["network_scope"],
            "user_agent": s["user_agent"],
        }
        dataset.append(feature)

    return {
        "generated_at_utc": utc_now_iso(),
        "days": days,
        "session_count": len(dataset),
        "rows": dataset,
    }


def export_ml_dataset_csv(export_dir, dataset):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"ml_dataset_{ts}.csv"

    rows = dataset.get("rows", [])
    fieldnames = [
        "session_id",
        "visitor_key",
        "category",
        "hits",
        "unique_pages",
        "depth_max",
        "duration_sec",
        "avg_gap_sec",
        "revisit_rate",
        "robots_seen",
        "sitemap_seen",
        "disallowed_seen",
        "network_scope",
        "user_agent",
    ]

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return out


def export_ml_dataset_json(export_dir, dataset):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"ml_dataset_{ts}.json"
    out.write_text(json.dumps(dataset, ensure_ascii=True, indent=2), encoding="utf-8")
    return out


def bot_ip_inventory(mode="anonymized", limit=500000):
    db = get_db()
    allow_raw = bool(current_app.config.get("ALLOW_RAW_IP_EXPORT", False))

    rows = db.execute(
        """
        SELECT ip_anonymized, ip_raw, category, user_agent, MIN(ts_utc) AS first_seen, MAX(ts_utc) AS last_seen, COUNT(*) AS hits
        FROM requests
        WHERE category != 'human_browser'
        GROUP BY ip_anonymized, ip_raw, category, user_agent
        ORDER BY hits DESC
        LIMIT ?
        """,
        (int(limit),),
    ).fetchall()

    items = []
    for row in rows:
        ip_value = row["ip_anonymized"]
        if mode == "raw" and allow_raw and row["ip_raw"]:
            ip_value = row["ip_raw"]
        items.append(
            {
                "ip": ip_value,
                "ip_anonymized": row["ip_anonymized"],
                "ip_raw_available": bool(row["ip_raw"]),
                "category": row["category"],
                "user_agent": row["user_agent"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "hits": row["hits"],
            }
        )

    return {
        "generated_at_utc": utc_now_iso(),
        "mode": "raw" if mode == "raw" and allow_raw else "anonymized",
        "raw_allowed": allow_raw,
        "count": len(items),
        "items": items,
    }


def export_bot_ip_inventory_csv(export_dir, inventory):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"bot_ips_{inventory.get('mode', 'anonymized')}_{ts}.csv"

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "ip",
                "ip_anonymized",
                "ip_raw_available",
                "category",
                "user_agent",
                "first_seen",
                "last_seen",
                "hits",
            ]
        )
        for item in inventory.get("items", []):
            writer.writerow(
                [
                    item.get("ip"),
                    item.get("ip_anonymized"),
                    item.get("ip_raw_available"),
                    item.get("category"),
                    item.get("user_agent"),
                    item.get("first_seen"),
                    item.get("last_seen"),
                    item.get("hits"),
                ]
            )
    return out


def export_bot_ip_inventory_json(export_dir, inventory):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"bot_ips_{inventory.get('mode', 'anonymized')}_{ts}.json"
    out.write_text(json.dumps(inventory, ensure_ascii=True, indent=2), encoding="utf-8")
    return out


def _finalize_session(visitor_key, seq):
    start_ts = seq[0][0]
    end_ts = seq[-1][0]
    rows = [item[1] for item in seq]
    paths = [row["path"] for row in rows]
    gaps = [
        (seq[i][0] - seq[i - 1][0]).total_seconds()
        for i in range(1, len(seq))
    ]

    path_counts = Counter(paths)
    revisits = sum(v - 1 for v in path_counts.values() if v > 1)

    session_id = f"{visitor_key}:{int(start_ts.timestamp())}"
    duration_sec = (end_ts - start_ts).total_seconds()

    category_counts = Counter(row["category"] or "unknown_bot" for row in rows)
    category = category_counts.most_common(1)[0][0] if category_counts else "unknown_bot"

    return {
        "session_id": session_id,
        "visitor_key": visitor_key,
        "start_ts": start_ts.isoformat(),
        "end_ts": end_ts.isoformat(),
        "duration_sec": round(duration_sec, 3),
        "hits": len(rows),
        "unique_pages": len(path_counts),
        "depth_max": max((p.count("/") for p in paths), default=0),
        "avg_gap_sec": round(sum(gaps) / len(gaps), 3) if gaps else 0.0,
        "revisit_rate": round(revisits / len(rows), 4) if rows else 0.0,
        "robots_seen": "/robots.txt" in paths,
        "sitemap_seen": "/sitemap.xml" in paths,
        "disallowed_seen": "/reseau/profondeur/13" in paths,
        "category": category,
        "user_agent": (rows[-1]["user_agent"] or "")[:180],
        "network_scope": rows[-1]["network_scope"] or "unknown",
    }


def _category_window_metrics(db, start_iso, end_iso):
    rows = db.execute(
        """
        SELECT category, COUNT(*) AS hits, COUNT(DISTINCT visitor_key) AS visitors
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        GROUP BY category
        """,
        (start_iso, end_iso),
    ).fetchall()
    return {
        row["category"]: {"hits": row["hits"], "visitors": row["visitors"]}
        for row in rows
    }


def _post_webhook(url, payload):
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlrequest.urlopen(req, timeout=8) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _suspicious_count_sql(has_end):
    conditions = ["LOWER(path) LIKE LOWER(?)" for _ in SUSPICIOUS_PATTERNS]
    where_paths = " OR ".join(conditions)
    if has_end:
        return (
            "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND ts_utc < ? AND ("
            + where_paths
            + ")"
        )
    return "SELECT COUNT(*) FROM requests WHERE ts_utc >= ? AND (" + where_paths + ")"


def _suspicious_args(start_iso, end_iso):
    args = [start_iso]
    if end_iso is not None:
        args.append(end_iso)
    args.extend(SUSPICIOUS_PATTERNS)
    return tuple(args)


def _day_bounds(day_utc):
    day_dt = datetime.strptime(day_utc, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return day_dt.isoformat(), (day_dt + timedelta(days=1)).isoformat()


def _scalar(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    if row is None:
        return 0
    return row[0]


def _to_dt(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
