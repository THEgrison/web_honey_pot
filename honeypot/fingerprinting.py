import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import get_db


def behavioural_fingerprinting(limit=300, days=30, scoring=None, filters=None):
    db = get_db()
    limit = max(1, min(int(limit), 2000))
    days = max(1, min(int(days), 365))
    scoring = _merge_scoring(scoring or {})
    filters = filters or {}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = db.execute(
        """
        SELECT visitor_key, ts_utc, path, category, user_agent
        FROM requests
        WHERE ts_utc >= ?
        ORDER BY visitor_key ASC, ts_utc ASC
        """,
        (cutoff,),
    ).fetchall()

    if not rows:
        return {
            "window_days": days,
            "scoring": scoring,
            "filters": filters,
            "summary": {
                "total_profiles": 0,
                "avg_sophistication_score": 0.0,
                "strategy_distribution": {},
                "robots_respect_rate": 0.0,
                "avg_depth": 0.0,
                "avg_requests_per_minute": 0.0,
                "avg_revisit_rate": 0.0,
                "js_capable_profiles": 0,
                "cookies_capable_profiles": 0,
            },
            "top_profiles": [],
            "profiles": [],
        }

    grouped = defaultdict(list)
    visitor_category = {}
    visitor_ua = {}
    for row in rows:
        key = row["visitor_key"]
        grouped[key].append((row["ts_utc"], row["path"]))
        visitor_category[key] = row["category"] or "unknown_bot"
        visitor_ua[key] = row["user_agent"] or ""

    js_capable, cookie_capable = _capability_sets(cutoff)

    profiles = []
    for key, seq in grouped.items():
        profile = _build_profile(
            key,
            seq,
            visitor_category.get(key, "unknown_bot"),
            visitor_ua.get(key, ""),
            key in js_capable,
            key in cookie_capable,
            scoring,
        )
        if _matches_filters(profile, filters):
            profiles.append(profile)

    profiles.sort(key=lambda p: p["sophistication_score"], reverse=True)
    trimmed = profiles[:limit]

    if not trimmed:
        return {
            "window_days": days,
            "scoring": scoring,
            "filters": filters,
            "summary": {
                "total_profiles": 0,
                "avg_sophistication_score": 0.0,
                "strategy_distribution": {},
                "robots_respect_rate": 0.0,
                "avg_depth": 0.0,
                "avg_requests_per_minute": 0.0,
                "avg_revisit_rate": 0.0,
                "js_capable_profiles": 0,
                "cookies_capable_profiles": 0,
            },
            "top_profiles": [],
            "profiles": [],
        }

    strategy_distribution = Counter(item["exploration_strategy"] for item in trimmed)
    consulted = [p for p in trimmed if p["conventions"]["consulted_robots_txt"]]
    respected = [p for p in consulted if p["conventions"]["respected_robots_txt"]]

    summary = {
        "total_profiles": len(trimmed),
        "avg_sophistication_score": round(
            sum(item["sophistication_score"] for item in trimmed) / len(trimmed), 2
        ),
        "strategy_distribution": dict(strategy_distribution),
        "robots_respect_rate": round(len(respected) / len(consulted), 4) if consulted else 0.0,
        "avg_depth": round(sum(item["depth_max"] for item in trimmed) / len(trimmed), 2),
        "avg_requests_per_minute": round(
            sum(item["speed"]["requests_per_minute"] for item in trimmed) / len(trimmed), 3
        ),
        "avg_revisit_rate": round(
            sum(item["revisit"]["revisit_rate"] for item in trimmed) / len(trimmed), 4
        ),
        "js_capable_profiles": sum(1 for p in trimmed if p["javascript_capable"]),
        "cookies_capable_profiles": sum(1 for p in trimmed if p["cookies_capable"]),
    }

    top_profiles = [
        {
            "visitor_key": p["visitor_key"],
            "sophistication_score": p["sophistication_score"],
            "exploration_strategy": p["exploration_strategy"],
            "depth_max": p["depth_max"],
            "requests_per_minute": p["speed"]["requests_per_minute"],
            "revisit_rate": p["revisit"]["revisit_rate"],
            "category": p["category"],
            "user_agent": p["user_agent"][:120],
        }
        for p in trimmed[:25]
    ]

    return {
        "window_days": days,
        "scoring": scoring,
        "filters": filters,
        "summary": summary,
        "top_profiles": top_profiles,
        "profiles": trimmed,
    }


def export_fingerprinting_json(export_dir, result):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"fingerprinting_filtered_{ts}.json"
    out.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    return out


def export_fingerprinting_csv(export_dir, result):
    Path(export_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(export_dir) / f"fingerprinting_filtered_{ts}.csv"
    profiles = result.get("profiles", [])

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "visitor_key",
                "category",
                "sophistication_score",
                "exploration_strategy",
                "depth_max",
                "requests_per_minute",
                "avg_interval_sec",
                "request_count",
                "unique_pages",
                "revisit_rate",
                "consulted_robots_txt",
                "respected_robots_txt",
                "consulted_sitemap",
                "visited_disallowed",
                "javascript_capable",
                "cookies_capable",
                "user_agent",
            ]
        )
        for p in profiles:
            writer.writerow(
                [
                    p.get("visitor_key"),
                    p.get("category"),
                    p.get("sophistication_score"),
                    p.get("exploration_strategy"),
                    p.get("depth_max"),
                    (p.get("speed") or {}).get("requests_per_minute"),
                    (p.get("speed") or {}).get("avg_interval_sec"),
                    (p.get("speed") or {}).get("request_count"),
                    (p.get("pages") or {}).get("unique_pages"),
                    (p.get("revisit") or {}).get("revisit_rate"),
                    (p.get("conventions") or {}).get("consulted_robots_txt"),
                    (p.get("conventions") or {}).get("respected_robots_txt"),
                    (p.get("conventions") or {}).get("consulted_sitemap"),
                    (p.get("conventions") or {}).get("visited_disallowed"),
                    p.get("javascript_capable"),
                    p.get("cookies_capable"),
                    p.get("user_agent"),
                ]
            )
    return out


def _build_profile(
    visitor_key,
    seq,
    category,
    user_agent,
    js_capable,
    cookies_capable,
    scoring,
):
    paths = [p for _, p in seq]
    hits = len(paths)
    unique_pages = len(set(paths))
    depth_max = max((path.count("/") for path in paths), default=0)

    intervals = []
    for idx in range(1, len(seq)):
        prev_dt = _to_dt(seq[idx - 1][0])
        cur_dt = _to_dt(seq[idx][0])
        intervals.append((cur_dt - prev_dt).total_seconds())

    avg_interval = (sum(intervals) / len(intervals)) if intervals else 0.0
    req_per_min = (60.0 / avg_interval) if avg_interval > 0 else float(hits)

    revisits = max(0, hits - unique_pages)
    revisit_rate = (revisits / hits) if hits else 0.0

    consulted_robots = "/robots.txt" in paths
    consulted_sitemap = "/sitemap.xml" in paths
    visited_disallowed = "/reseau/profondeur/13" in paths
    respected_robots = consulted_robots and not visited_disallowed

    strategy = _classify_strategy(
        scoring,
        depth_max=depth_max,
        unique_pages=unique_pages,
        hits=hits,
        revisit_rate=revisit_rate,
        req_per_min=req_per_min,
    )

    sophistication = _score_sophistication(
        scoring,
        depth_max=depth_max,
        unique_pages=unique_pages,
        consulted_robots=consulted_robots,
        respected_robots=respected_robots,
        consulted_sitemap=consulted_sitemap,
        js_capable=js_capable,
        cookies_capable=cookies_capable,
        avg_interval=avg_interval,
        revisit_rate=revisit_rate,
    )

    return {
        "visitor_key": visitor_key,
        "category": category,
        "user_agent": user_agent,
        "sophistication_score": sophistication,
        "exploration_strategy": strategy,
        "speed": {
            "avg_interval_sec": round(avg_interval, 3),
            "requests_per_minute": round(req_per_min, 3),
            "request_count": hits,
        },
        "depth_max": int(depth_max),
        "pages": {
            "unique_pages": unique_pages,
            "total_hits": hits,
        },
        "conventions": {
            "consulted_robots_txt": consulted_robots,
            "respected_robots_txt": respected_robots,
            "consulted_sitemap": consulted_sitemap,
            "visited_disallowed": visited_disallowed,
        },
        "javascript_capable": bool(js_capable),
        "cookies_capable": bool(cookies_capable),
        "revisit": {
            "revisit_count": revisits,
            "revisit_rate": round(revisit_rate, 4),
        },
    }


def _classify_strategy(scoring, depth_max, unique_pages, hits, revisit_rate, req_per_min):
    if hits <= 2:
        return "insufficient_data"
    if req_per_min > scoring["speed_fast_rpm"]:
        return "high_speed_scan"
    if depth_max >= scoring["depth_first_min_depth"] and unique_pages >= max(
        8, int(hits * 0.7)
    ):
        return "depth_first"
    if (
        unique_pages >= scoring["breadth_min_unique_pages"]
        and depth_max <= scoring["breadth_max_depth"]
    ):
        return "breadth_first"
    if revisit_rate >= scoring["iterative_revisit_threshold"]:
        return "iterative_revisit"
    return "mixed_walk"


def _score_sophistication(
    scoring,
    depth_max,
    unique_pages,
    consulted_robots,
    respected_robots,
    consulted_sitemap,
    js_capable,
    cookies_capable,
    avg_interval,
    revisit_rate,
):
    depth_score = min(depth_max / float(scoring["depth_target"]), 1.0) * float(
        scoring["weight_depth"]
    )
    coverage_score = min(unique_pages / float(scoring["coverage_target"]), 1.0) * float(
        scoring["weight_coverage"]
    )

    convention_score = 0.0
    if consulted_robots:
        convention_score += float(scoring["weight_consult_robots"])
    if respected_robots:
        convention_score += float(scoring["weight_respect_robots"])
    if consulted_sitemap:
        convention_score += float(scoring["weight_consult_sitemap"])

    capability_score = (
        (float(scoring["weight_js_capable"]) if js_capable else 0.0)
        + (float(scoring["weight_cookies_capable"]) if cookies_capable else 0.0)
    )

    if avg_interval <= 0:
        pace_score = float(scoring["weight_pace_neutral"])
    elif float(scoring["pace_good_min_sec"]) <= avg_interval <= float(
        scoring["pace_good_max_sec"]
    ):
        pace_score = float(scoring["weight_pace_good"])
    elif avg_interval < float(scoring["pace_good_min_sec"]):
        pace_score = float(scoring["weight_pace_too_fast"])
    else:
        pace_score = float(scoring["weight_pace_slow"])

    revisit_target = float(scoring["revisit_target"])
    revisit_sensitivity = float(scoring["revisit_sensitivity"])
    revisit_score = max(
        0.0,
        float(scoring["weight_revisit"])
        - abs(revisit_rate - revisit_target) * revisit_sensitivity,
    )

    total = depth_score + coverage_score + convention_score + capability_score + pace_score + revisit_score
    return round(min(total, 100.0), 2)


def _matches_filters(profile, filters):
    category = (filters.get("category") or "").strip()
    if category and category != "all" and profile["category"] != category:
        return False

    strategy = (filters.get("strategy") or "").strip()
    if strategy and strategy != "all" and profile["exploration_strategy"] != strategy:
        return False

    js_required = filters.get("js_capable")
    if js_required is not None and profile["javascript_capable"] != js_required:
        return False

    cookies_required = filters.get("cookies_capable")
    if cookies_required is not None and profile["cookies_capable"] != cookies_required:
        return False

    min_score = filters.get("min_score")
    if min_score is not None and profile["sophistication_score"] < float(min_score):
        return False

    max_score = filters.get("max_score")
    if max_score is not None and profile["sophistication_score"] > float(max_score):
        return False

    min_depth = filters.get("min_depth")
    if min_depth is not None and profile["depth_max"] < int(min_depth):
        return False

    min_rpm = filters.get("min_rpm")
    if min_rpm is not None and profile["speed"]["requests_per_minute"] < float(min_rpm):
        return False

    max_rpm = filters.get("max_rpm")
    if max_rpm is not None and profile["speed"]["requests_per_minute"] > float(max_rpm):
        return False

    return True


def _merge_scoring(raw):
    defaults = {
        "depth_target": 20,
        "coverage_target": 30,
        "speed_fast_rpm": 80,
        "depth_first_min_depth": 12,
        "breadth_min_unique_pages": 25,
        "breadth_max_depth": 8,
        "iterative_revisit_threshold": 0.35,
        "revisit_target": 0.15,
        "revisit_sensitivity": 40,
        "pace_good_min_sec": 0.5,
        "pace_good_max_sec": 8.0,
        "weight_depth": 20,
        "weight_coverage": 20,
        "weight_consult_robots": 10,
        "weight_respect_robots": 10,
        "weight_consult_sitemap": 5,
        "weight_js_capable": 20,
        "weight_cookies_capable": 10,
        "weight_pace_good": 15,
        "weight_pace_too_fast": 5,
        "weight_pace_slow": 10,
        "weight_pace_neutral": 8,
        "weight_revisit": 10,
    }
    merged = defaults.copy()
    for key, value in raw.items():
        if key in merged and value is not None:
            merged[key] = value
    return merged


def _capability_sets(cutoff_iso):
    db = get_db()
    js_rows = db.execute(
        """
        SELECT DISTINCT visitor_key
        FROM capability_events
        WHERE ts_utc >= ? AND event_name='js_executed'
        """,
        (cutoff_iso,),
    ).fetchall()
    cookie_rows = db.execute(
        """
        SELECT DISTINCT visitor_key
        FROM capability_events
        WHERE ts_utc >= ? AND event_name='cookies_supported' AND event_value='1'
        """,
        (cutoff_iso,),
    ).fetchall()
    return (
        {row["visitor_key"] for row in js_rows},
        {row["visitor_key"] for row in cookie_rows},
    )


def _to_dt(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
