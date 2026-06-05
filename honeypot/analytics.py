import csv
import json
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import get_db, json_dumps_safe, utc_now_iso


def overview_stats():
    db = get_db()
    total_visits = db.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]
    unique_visitors = db.execute(
        "SELECT COUNT(DISTINCT visitor_key) AS c FROM requests"
    ).fetchone()["c"]
    unique_ua = db.execute(
        "SELECT COUNT(DISTINCT user_agent) AS c FROM requests"
    ).fetchone()["c"]

    categories = db.execute(
        "SELECT category, COUNT(*) AS c FROM requests GROUP BY category ORDER BY c DESC"
    ).fetchall()

    return {
        "total_visits": total_visits,
        "unique_visitors": unique_visitors,
        "unique_user_agents": unique_ua,
        "category_distribution": {row["category"]: row["c"] for row in categories},
    }


def top_user_agents(limit=20):
    db = get_db()
    rows = db.execute(
        """
        SELECT COALESCE(user_agent, 'unknown') AS user_agent, COUNT(*) AS c
        FROM requests
        GROUP BY user_agent
        ORDER BY c DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [{"user_agent": r["user_agent"], "count": r["c"]} for r in rows]


def path_sequences(limit_visitors=200):
    db = get_db()
    rows = db.execute(
        """
        SELECT visitor_key, path, ts_utc
        FROM requests
        ORDER BY visitor_key ASC, ts_utc ASC
        """
    ).fetchall()

    per_visitor = defaultdict(list)
    for row in rows:
        per_visitor[row["visitor_key"]].append((row["ts_utc"], row["path"]))

    edges = Counter()
    sequence_stats = []
    for idx, (visitor_key, seq) in enumerate(per_visitor.items()):
        if idx >= limit_visitors:
            break
        paths = [item[1] for item in seq]
        for i in range(len(paths) - 1):
            edges[(paths[i], paths[i + 1])] += 1
        sequence_stats.append(
            {
                "visitor_key": visitor_key,
                "pages": len(set(paths)),
                "steps": len(paths),
                "depth_estimate": max((p.count("/") for p in paths), default=0),
                "sequence": paths[:30],
            }
        )

    edge_list = [
        {"source": source, "target": target, "weight": weight}
        for (source, target), weight in edges.most_common(300)
    ]

    return {"edges": edge_list, "visitor_sequences": sequence_stats}


def crawl_behavior_metrics():
    db = get_db()

    depth_max = db.execute(
        "SELECT MAX(LENGTH(path) - LENGTH(REPLACE(path, '/', ''))) AS m FROM requests"
    ).fetchone()["m"]

    pages_avg = db.execute(
        """
        SELECT AVG(cnt) AS a FROM (
            SELECT visitor_key, COUNT(*) AS cnt
            FROM requests
            GROUP BY visitor_key
        )
        """
    ).fetchone()["a"]

    js_exec_count = db.execute(
        "SELECT COUNT(*) AS c FROM capability_events WHERE event_name='js_executed'"
    ).fetchone()["c"]

    visitor_count = db.execute(
        "SELECT COUNT(DISTINCT visitor_key) AS c FROM requests"
    ).fetchone()["c"]

    js_rate = (js_exec_count / visitor_count) if visitor_count else 0.0

    deltas = db.execute(
        """
        SELECT visitor_key, ts_utc
        FROM requests
        ORDER BY visitor_key ASC, ts_utc ASC
        """
    ).fetchall()
    last = {}
    diff_seconds = []
    for row in deltas:
        key = row["visitor_key"]
        current = _to_dt(row["ts_utc"])
        prev = last.get(key)
        if prev is not None:
            diff_seconds.append((current - prev).total_seconds())
        last[key] = current

    avg_time_between = sum(diff_seconds) / len(diff_seconds) if diff_seconds else 0.0

    return {
        "max_depth": int(depth_max or 0),
        "avg_pages_per_visitor": round(float(pages_avg or 0.0), 2),
        "avg_time_between_requests_sec": round(avg_time_between, 2),
        "js_execution_rate": round(js_rate, 4),
    }


def robots_compliance_stats():
    db = get_db()
    robots_hits = db.execute(
        "SELECT COUNT(*) AS c FROM requests WHERE path='/robots.txt'"
    ).fetchone()["c"]
    sitemap_hits = db.execute(
        "SELECT COUNT(*) AS c FROM requests WHERE path='/sitemap.xml'"
    ).fetchone()["c"]

    disallowed_visits = db.execute(
        "SELECT COUNT(*) AS c FROM requests WHERE path='/reseau/profondeur/13'"
    ).fetchone()["c"]

    robots_known_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM requests
        WHERE path='/robots.txt'
        """
    ).fetchone()["c"]

    disallowed_known_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM requests
        WHERE path='/reseau/profondeur/13'
        """
    ).fetchone()["c"]

    respected_visitors = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM (
            SELECT visitor_key
            FROM requests
            GROUP BY visitor_key
            HAVING SUM(CASE WHEN path='/robots.txt' THEN 1 ELSE 0 END) > 0
               AND SUM(CASE WHEN path='/reseau/profondeur/13' THEN 1 ELSE 0 END) = 0
        )
        """
    ).fetchone()["c"]

    return {
        "robots_txt_hits": robots_hits,
        "sitemap_hits": sitemap_hits,
        "disallowed_hits": disallowed_visits,
        "visitors_consulted_robots": robots_known_visitors,
        "visitors_visited_disallowed_13": disallowed_known_visitors,
        "visitors_respected_robots": respected_visitors,
    }


def recurring_behavior():
    db = get_db()
    rows = db.execute(
        """
        SELECT visitor_key, GROUP_CONCAT(path, '->') AS sig, COUNT(*) AS c
        FROM (
            SELECT visitor_key, path
            FROM requests
            ORDER BY visitor_key, ts_utc
        )
        GROUP BY visitor_key
        """
    ).fetchall()

    signatures = Counter()
    for row in rows:
        signature = (row["sig"] or "")[:500]
        signatures[signature] += 1

    top = []
    for sig, count in signatures.most_common(20):
        if not sig:
            continue
        top.append({"signature": sig, "visitors": count})
    return top


def family_comparison():
    db = get_db()
    rows = db.execute(
        """
        SELECT category, COUNT(*) AS hits, COUNT(DISTINCT visitor_key) AS visitors,
               AVG(processing_ms) AS avg_ms
        FROM requests
        GROUP BY category
        ORDER BY hits DESC
        """
    ).fetchall()
    return [
        {
            "category": row["category"],
            "hits": row["hits"],
            "visitors": row["visitors"],
            "avg_processing_ms": round(float(row["avg_ms"] or 0.0), 2),
        }
        for row in rows
    ]


def advanced_crawler_metrics():
    behavior = crawl_behavior_metrics()
    robots = robots_compliance_stats()
    db = get_db()

    visitor_count = db.execute(
        "SELECT COUNT(DISTINCT visitor_key) AS c FROM requests"
    ).fetchone()["c"]

    sitemap_visitors = db.execute(
        "SELECT COUNT(DISTINCT visitor_key) AS c FROM requests WHERE path='/sitemap.xml'"
    ).fetchone()["c"]

    cookie_supported_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM capability_events
        WHERE event_name='cookies_supported' AND event_value='1'
        """
    ).fetchone()["c"]

    cookies_support_rate = (
        cookie_supported_visitors / visitor_count if visitor_count else 0.0
    )
    sitemap_consultation_rate = sitemap_visitors / visitor_count if visitor_count else 0.0

    transitions = db.execute(
        """
        SELECT visitor_key, path, ts_utc
        FROM requests
        ORDER BY visitor_key ASC, ts_utc ASC
        """
    ).fetchall()

    last_path = {}
    edge_counter = Counter()
    visitor_path_counter = defaultdict(Counter)

    for row in transitions:
        key = row["visitor_key"]
        path = row["path"]
        prev = last_path.get(key)
        if prev is not None:
            edge_counter[(prev, path)] += 1
        last_path[key] = path
        visitor_path_counter[key][path] += 1

    top_orders = [
        {"from": source, "to": target, "count": count}
        for (source, target), count in edge_counter.most_common(20)
    ]

    revisiting_visitors = 0
    total_revisits = 0
    for counter in visitor_path_counter.values():
        revisits = sum((v - 1) for v in counter.values() if v > 1)
        if revisits > 0:
            revisiting_visitors += 1
            total_revisits += revisits

    avg_revisits_per_visitor = total_revisits / visitor_count if visitor_count else 0.0
    revisit_rate = revisiting_visitors / visitor_count if visitor_count else 0.0

    return {
        "avg_time_between_requests_sec": behavior["avg_time_between_requests_sec"],
        "max_depth": behavior["max_depth"],
        "robots_txt_respect": {
            "visitors_respected": robots["visitors_respected_robots"],
            "visitors_consulted": robots["visitors_consulted_robots"],
            "rate": (
                robots["visitors_respected_robots"] / robots["visitors_consulted_robots"]
                if robots["visitors_consulted_robots"]
                else 0.0
            ),
        },
        "sitemap_consulted_visitors": sitemap_visitors,
        "sitemap_consultation_rate": round(sitemap_consultation_rate, 4),
        "js_execution_rate": behavior["js_execution_rate"],
        "cookies_support_rate": round(cookies_support_rate, 4),
        "link_exploration_order_top": top_orders,
        "revisit_frequency": {
            "revisiting_visitors": revisiting_visitors,
            "revisit_rate": round(revisit_rate, 4),
            "avg_revisits_per_visitor": round(avg_revisits_per_visitor, 3),
        },
    }


def realtime_activity(window_seconds=300):
    db = get_db()
    cutoff = _utc_cutoff_iso(window_seconds)

    active_rows = db.execute(
        """
        SELECT r.visitor_key, r.category, r.user_agent, r.path, r.ts_utc
        FROM requests r
        JOIN (
            SELECT visitor_key, MAX(id) AS max_id
            FROM requests
            WHERE ts_utc >= ?
            GROUP BY visitor_key
        ) latest ON r.id = latest.max_id
        """,
        (cutoff,),
    ).fetchall()

    category_counts = Counter(row["category"] or "unknown_bot" for row in active_rows)
    bots_active = sum(
        count for category, count in category_counts.items() if category != "human_browser"
    )

    js_recent = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM capability_events
        WHERE event_name='js_executed' AND ts_utc >= ?
        """,
        (cutoff,),
    ).fetchone()["c"]

    suspicious = suspicious_access_summary(window_seconds)

    return {
        "window_seconds": window_seconds,
        "active_visitors": len(active_rows),
        "active_bots": bots_active,
        "active_by_category": dict(category_counts),
        "active_visitors_with_js": js_recent,
        "active_samples": [
            {
                "visitor_key": row["visitor_key"],
                "category": row["category"],
                "last_path": row["path"],
                "last_seen": row["ts_utc"],
                "user_agent": (row["user_agent"] or "")[:140],
            }
            for row in active_rows[:50]
        ],
        "suspicious": suspicious,
    }


def suspicious_access_summary(window_seconds=300):
    db = get_db()
    cutoff_window = _utc_cutoff_iso(window_seconds)
    cutoff_day = _utc_cutoff_iso(24 * 3600)

    patterns = [
        "%/admin%",
        "%/wp-admin%",
        "%/phpmyadmin%",
        "%/manager%",
        "%/backend%",
        "%/cpanel%",
        "%/panel%",
        "%.php%",
        "%.asp%",
        "%.aspx%",
        "%.jsp%",
        "%/.env%",
        "%/cgi-bin%",
        "%/xmlrpc.php%",
        "%/shell%",
    ]

    recent = _suspicious_counts(cutoff_window, patterns)
    daily = _suspicious_counts(cutoff_day, patterns)

    top_paths_rows = db.execute(
        _suspicious_top_paths_query(patterns),
        (cutoff_day, *patterns),
    ).fetchall()

    return {
        "recent_window": recent,
        "last_24h": daily,
        "top_suspicious_paths_24h": [
            {"path": row["path"], "hits": row["c"]} for row in top_paths_rows
        ],
    }


def export_json(export_dir):
    data = {
        "generated_at_utc": utc_now_iso(),
        "overview": overview_stats(),
        "top_user_agents": top_user_agents(),
        "path_sequences": path_sequences(),
        "behavior": crawl_behavior_metrics(),
        "advanced": advanced_crawler_metrics(),
        "realtime": realtime_activity(),
        "robots": robots_compliance_stats(),
        "recurring": recurring_behavior(),
        "families": family_comparison(),
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"export_{ts}.json"
    out.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
    return out


def export_csv(export_dir):
    db = get_db()
    rows = db.execute(
        """
        SELECT ts_utc, visitor_key, ip_anonymized, path, method, user_agent,
               referer, status_code, processing_ms, category
        FROM requests
        ORDER BY id DESC
        LIMIT 100000
        """
    ).fetchall()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"export_{ts}.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "ts_utc",
                "visitor_key",
                "ip_anonymized",
                "path",
                "method",
                "user_agent",
                "referer",
                "status_code",
                "processing_ms",
                "category",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row["ts_utc"],
                    row["visitor_key"],
                    row["ip_anonymized"],
                    row["path"],
                    row["method"],
                    row["user_agent"],
                    row["referer"],
                    row["status_code"],
                    row["processing_ms"],
                    row["category"],
                ]
            )
    return out


def generate_daily_report(report_dir):
    now = datetime.now(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    return generate_daily_report_for_day(report_dir, day)


def generate_daily_report_for_day(report_dir, day_utc):
    db = get_db()
    report = {
        "day_utc": day_utc,
        "generated_at_utc": utc_now_iso(),
        "day_metrics": daily_global_metrics(day_utc),
        "overview_global": overview_stats(),
        "behavior_global": crawl_behavior_metrics(),
        "advanced_global": advanced_crawler_metrics(),
        "robots_global": robots_compliance_stats(),
        "families_global": family_comparison(),
    }

    Path(report_dir).mkdir(parents=True, exist_ok=True)
    out = Path(report_dir) / f"daily_{day_utc}.json"
    out.write_text(json_dumps_safe(report), encoding="utf-8")

    db.execute(
        """
        INSERT INTO daily_reports(day_utc, generated_at_utc, content_json)
        VALUES (?, ?, ?)
        ON CONFLICT(day_utc) DO UPDATE SET
        generated_at_utc=excluded.generated_at_utc,
        content_json=excluded.content_json
        """,
        (day_utc, report["generated_at_utc"], json_dumps_safe(report)),
    )
    db.commit()
    return out, report


def export_daily_reports_zip(report_dir, days=7):
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    days = max(1, min(int(days), 365))

    generated_files = []
    now = datetime.now(timezone.utc)
    for offset in range(days):
        day = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
        out, _ = generate_daily_report_for_day(report_dir, day)
        generated_files.append(out)

    ts = now.strftime("%Y%m%dT%H%M%SZ")
    zip_path = Path(report_dir) / f"daily_reports_{days}d_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in generated_files:
            zf.write(file_path, arcname=file_path.name)

    return zip_path, generated_files


def daily_global_metrics(day_utc):
    start_iso, end_iso = _day_bounds_iso(day_utc)
    db = get_db()

    total_requests = db.execute(
        "SELECT COUNT(*) AS c FROM requests WHERE ts_utc >= ? AND ts_utc < ?",
        (start_iso, end_iso),
    ).fetchone()["c"]

    unique_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    unique_user_agents = db.execute(
        """
        SELECT COUNT(DISTINCT user_agent) AS c
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    categories = db.execute(
        """
        SELECT category, COUNT(*) AS c
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        GROUP BY category
        ORDER BY c DESC
        """,
        (start_iso, end_iso),
    ).fetchall()
    category_distribution = {row["category"]: row["c"] for row in categories}
    bot_hits = sum(
        count for category, count in category_distribution.items() if category != "human_browser"
    )

    robots_hits = db.execute(
        """
        SELECT COUNT(*) AS c FROM requests
        WHERE ts_utc >= ? AND ts_utc < ? AND path='/robots.txt'
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]
    sitemap_hits = db.execute(
        """
        SELECT COUNT(*) AS c FROM requests
        WHERE ts_utc >= ? AND ts_utc < ? AND path='/sitemap.xml'
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    robots_consulted_visitors = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM (
            SELECT visitor_key
            FROM requests
            WHERE ts_utc >= ? AND ts_utc < ?
            GROUP BY visitor_key
            HAVING SUM(CASE WHEN path='/robots.txt' THEN 1 ELSE 0 END) > 0
        )
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    robots_respected_visitors = db.execute(
        """
        SELECT COUNT(*) AS c
        FROM (
            SELECT visitor_key
            FROM requests
            WHERE ts_utc >= ? AND ts_utc < ?
            GROUP BY visitor_key
            HAVING SUM(CASE WHEN path='/robots.txt' THEN 1 ELSE 0 END) > 0
               AND SUM(CASE WHEN path='/reseau/profondeur/13' THEN 1 ELSE 0 END) = 0
        )
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    js_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM capability_events
        WHERE ts_utc >= ? AND ts_utc < ? AND event_name='js_executed'
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]
    cookie_visitors = db.execute(
        """
        SELECT COUNT(DISTINCT visitor_key) AS c
        FROM capability_events
        WHERE ts_utc >= ? AND ts_utc < ?
          AND event_name='cookies_supported' AND event_value='1'
        """,
        (start_iso, end_iso),
    ).fetchone()["c"]

    depth_max = db.execute(
        """
        SELECT MAX(LENGTH(path) - LENGTH(REPLACE(path, '/', ''))) AS m
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        """,
        (start_iso, end_iso),
    ).fetchone()["m"]

    rows = db.execute(
        """
        SELECT visitor_key, path, ts_utc
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
        ORDER BY visitor_key ASC, ts_utc ASC
        """,
        (start_iso, end_iso),
    ).fetchall()

    per_visitor_paths = defaultdict(list)
    for row in rows:
        per_visitor_paths[row["visitor_key"]].append((row["ts_utc"], row["path"]))

    diffs = []
    edge_counter = Counter()
    revisits_total = 0
    revisiting_visitors = 0
    for seq in per_visitor_paths.values():
        path_counts = Counter()
        for i, (ts, path) in enumerate(seq):
            path_counts[path] += 1
            if i > 0:
                prev_ts, prev_path = seq[i - 1]
                diffs.append((_to_dt(ts) - _to_dt(prev_ts)).total_seconds())
                edge_counter[(prev_path, path)] += 1

        visitor_revisits = sum((v - 1) for v in path_counts.values() if v > 1)
        revisits_total += visitor_revisits
        if visitor_revisits > 0:
            revisiting_visitors += 1

    avg_time_between = sum(diffs) / len(diffs) if diffs else 0.0
    revisit_rate = revisiting_visitors / unique_visitors if unique_visitors else 0.0

    suspicious = suspicious_access_summary_for_interval(start_iso, end_iso)

    return {
        "day_utc": day_utc,
        "totals": {
            "requests": total_requests,
            "bot_requests": bot_hits,
            "unique_visitors": unique_visitors,
            "unique_user_agents": unique_user_agents,
        },
        "category_distribution": category_distribution,
        "behavior": {
            "avg_time_between_requests_sec": round(avg_time_between, 2),
            "max_depth": int(depth_max or 0),
            "top_link_transitions": [
                {"from": source, "to": target, "count": count}
                for (source, target), count in edge_counter.most_common(20)
            ],
            "revisit_frequency": {
                "revisiting_visitors": revisiting_visitors,
                "revisits_total": revisits_total,
                "revisit_rate": round(revisit_rate, 4),
            },
        },
        "compliance": {
            "robots_txt_hits": robots_hits,
            "sitemap_hits": sitemap_hits,
            "robots_consulted_visitors": robots_consulted_visitors,
            "robots_respected_visitors": robots_respected_visitors,
            "robots_respect_rate": (
                round(robots_respected_visitors / robots_consulted_visitors, 4)
                if robots_consulted_visitors
                else 0.0
            ),
            "sitemap_consultation_rate": (
                round(sitemap_hits / total_requests, 4) if total_requests else 0.0
            ),
        },
        "capabilities": {
            "js_execution_visitors": js_visitors,
            "cookies_supported_visitors": cookie_visitors,
            "js_execution_rate": round(js_visitors / unique_visitors, 4) if unique_visitors else 0.0,
            "cookies_support_rate": round(cookie_visitors / unique_visitors, 4)
            if unique_visitors
            else 0.0,
        },
        "suspicious": suspicious,
    }


def suspicious_access_summary_for_interval(start_iso, end_iso):
    patterns = [
        "%/admin%",
        "%/wp-admin%",
        "%/phpmyadmin%",
        "%/manager%",
        "%/backend%",
        "%/cpanel%",
        "%/panel%",
        "%.php%",
        "%.asp%",
        "%.aspx%",
        "%.jsp%",
        "%/.env%",
        "%/cgi-bin%",
        "%/xmlrpc.php%",
        "%/shell%",
    ]
    return {
        "counts": _suspicious_counts_interval(start_iso, end_iso, patterns),
        "top_paths": _suspicious_top_paths_interval(start_iso, end_iso, patterns),
    }


def _to_dt(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _utc_cutoff_iso(seconds_ago):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def _suspicious_counts(cutoff_iso, patterns):
    db = get_db()
    where_clauses = " OR ".join(["LOWER(path) LIKE LOWER(?)" for _ in patterns])

    sql = f"""
        SELECT COUNT(*) AS hits, COUNT(DISTINCT visitor_key) AS visitors
        FROM requests
        WHERE ts_utc >= ?
          AND ({where_clauses})
    """
    row = db.execute(sql, (cutoff_iso, *patterns)).fetchone()
    return {"hits": row["hits"], "visitors": row["visitors"]}


def _suspicious_top_paths_query(patterns):
    where_clauses = " OR ".join(["LOWER(path) LIKE LOWER(?)" for _ in patterns])
    return f"""
        SELECT path, COUNT(*) AS c
        FROM requests
        WHERE ts_utc >= ?
          AND ({where_clauses})
        GROUP BY path
        ORDER BY c DESC
        LIMIT 20
    """


def _day_bounds_iso(day_utc):
    day_dt = datetime.strptime(day_utc, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    start_iso = day_dt.isoformat()
    end_iso = (day_dt + timedelta(days=1)).isoformat()
    return start_iso, end_iso


def _suspicious_counts_interval(start_iso, end_iso, patterns):
    db = get_db()
    where_clauses = " OR ".join(["LOWER(path) LIKE LOWER(?)" for _ in patterns])
    sql = f"""
        SELECT COUNT(*) AS hits, COUNT(DISTINCT visitor_key) AS visitors
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
          AND ({where_clauses})
    """
    row = db.execute(sql, (start_iso, end_iso, *patterns)).fetchone()
    return {"hits": row["hits"], "visitors": row["visitors"]}


def _suspicious_top_paths_interval(start_iso, end_iso, patterns):
    db = get_db()
    where_clauses = " OR ".join(["LOWER(path) LIKE LOWER(?)" for _ in patterns])
    sql = f"""
        SELECT path, COUNT(*) AS c
        FROM requests
        WHERE ts_utc >= ? AND ts_utc < ?
          AND ({where_clauses})
        GROUP BY path
        ORDER BY c DESC
        LIMIT 20
    """
    rows = db.execute(sql, (start_iso, end_iso, *patterns)).fetchall()
    return [{"path": row["path"], "hits": row["c"]} for row in rows]
