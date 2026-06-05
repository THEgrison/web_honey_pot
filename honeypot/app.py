import logging
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urljoin

from flask import (
    Flask,
    Response,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from .analytics import (
    advanced_crawler_metrics,
    crawl_behavior_metrics,
    export_csv,
    export_daily_reports_zip,
    export_json,
    family_comparison,
    generate_daily_report,
    overview_stats,
    path_sequences,
    realtime_activity,
    recurring_behavior,
    robots_compliance_stats,
    top_user_agents,
)
from .classifiers import classify_user_agent
from .config import Config
from .db import (
    close_db,
    delete_fingerprint_preset,
    init_db,
    insert_capability_event,
    insert_request_log,
    list_fingerprint_presets,
    prune_request_logs,
    upsert_fingerprint_preset,
    utc_now_iso,
)
from .fingerprinting import (
    behavioural_fingerprinting,
    export_fingerprinting_csv,
    export_fingerprinting_json,
)
from .intelligence_v3 import (
    bot_ip_inventory,
    build_ml_dataset,
    build_sessions,
    daily_kpi_v3,
    detect_anomalies,
    detect_drift,
    export_bot_ip_inventory_csv,
    export_bot_ip_inventory_json,
    export_ml_dataset_csv,
    export_ml_dataset_json,
    infer_network_scope,
    run_alert_pipeline,
)
from .page_graph import build_graph, page_title_from_path
from .security import (
    anonymize_ip,
    check_dashboard_credentials,
    login_required,
    make_visitor_key,
    safe_int,
)


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    Path(app.config["EXPORT_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORT_DIR"]).mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)

    app.graph = build_graph(
        random_pages=app.config["RANDOM_NETWORK_PAGES"],
        links_per_page=app.config["RANDOM_NETWORK_LINKS_PER_PAGE"],
    )

    _configure_logging(app)

    @app.before_request
    def _before_request():
        request._start_time = time.perf_counter()

    @app.after_request
    def _after_request(response):
        try:
            _log_request(response)
        except Exception:
            app.logger.exception("failed to log request")
        return response

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    @app.route("/")
    def index():
        return render_template("index.html", graph=app.graph)

    @app.route("/reseau/<network>/<node>")
    def network_page(network, node):
        path = f"/reseau/{network}/{node}"
        links = app.graph.get(path)
        if links is None:
            return make_response("Not found", 404)
        return render_template(
            "network_page.html",
            page_path=path,
            title=page_title_from_path(path),
            links=links,
        )

    @app.route("/cap/tests")
    def capability_tests():
        return render_template("capability_tests.html")

    @app.route("/cap/test.css")
    def capability_css():
        _record_cap("css_loaded", "1")
        css = "body{--cap-color:#0a8f6a}.css-ok{color:var(--cap-color);font-weight:700}"
        return Response(css, mimetype="text/css")

    @app.route("/cap/pixel.png")
    def capability_pixel():
        _record_cap("image_loaded", "1")
        # 1x1 transparent PNG
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc``\x00\x00"
            b"\x00\x04\x00\x01\x0b\xe7\x02\x9d\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return Response(png, mimetype="image/png")

    @app.route("/cap/js-beacon", methods=["POST"])
    def capability_js_beacon():
        payload = request.get_json(silent=True) or {}
        _record_cap("js_executed", "1", payload)
        return jsonify({"ok": True})

    @app.route("/cap/cookie-check")
    def capability_cookie_check():
        has_cookie = request.cookies.get("hp_cookie_test") == "1"
        if has_cookie:
            _record_cap("cookies_supported", "1")
        else:
            _record_cap("cookies_supported", "0")
        resp = make_response(render_template("cookie_check.html", has_cookie=has_cookie))
        resp.set_cookie("hp_cookie_test", "1", max_age=3600, httponly=False, samesite="Lax")
        return resp

    @app.route("/cap/redirect-test")
    def capability_redirect():
        _record_cap("redirect_received", "1")
        return redirect(url_for("capability_redirect_target"), code=302)

    @app.route("/cap/redirect-target")
    def capability_redirect_target():
        _record_cap("redirect_followed", "1")
        return render_template("redirect_target.html")

    @app.route("/cap/relative-base")
    def relative_base():
        _record_cap("relative_link_page_seen", "1")
        return render_template("relative_links.html")

    @app.route("/robots.txt")
    def robots_txt():
        lines = [
            "User-agent: *",
            "Disallow: /dashboard",
            "Disallow: /reseau/profondeur/13",
            "Allow: /",
            "Sitemap: " + urljoin(request.url_root, "sitemap.xml"),
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    @app.route("/sitemap.xml")
    def sitemap_xml():
        urls = [urljoin(request.url_root, path.lstrip("/")) for path in sorted(app.graph.keys())]
        urls.extend(
            [
                urljoin(request.url_root, "cap/tests"),
                urljoin(request.url_root, "cap/cookie-check"),
                urljoin(request.url_root, "cap/redirect-test"),
                urljoin(request.url_root, "cap/relative-base"),
            ]
        )
        body = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
        ]
        for u in urls:
            body.append(f"  <url><loc>{u}</loc></url>")
        body.append("</urlset>")
        return Response("\n".join(body), mimetype="application/xml")

    @app.route("/dashboard/login", methods=["GET", "POST"])
    def dashboard_login():
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            if check_dashboard_credentials(username, password):
                session["dashboard_auth"] = True
                return redirect(url_for("dashboard"))
            error = "Identifiants invalides"
            return make_response(render_template("login.html", error=error), 401)
        return render_template("login.html", error=error)

    @app.route("/dashboard/logout")
    def dashboard_logout():
        session.pop("dashboard_auth", None)
        return redirect(url_for("dashboard_login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/api/stats/overview")
    @login_required
    def api_overview():
        return jsonify(overview_stats())

    @app.route("/api/stats/top-user-agents")
    @login_required
    def api_top_agents():
        limit = safe_int(request.args.get("limit", 20), default=20, min_value=1, max_value=100)
        return jsonify(top_user_agents(limit=limit))

    @app.route("/api/stats/path-map")
    @login_required
    def api_path_map():
        return jsonify(path_sequences())

    @app.route("/api/stats/behavior")
    @login_required
    def api_behavior():
        return jsonify(crawl_behavior_metrics())

    @app.route("/api/stats/advanced")
    @login_required
    def api_advanced():
        return jsonify(advanced_crawler_metrics())

    @app.route("/api/stats/robots")
    @login_required
    def api_robots():
        return jsonify(robots_compliance_stats())

    @app.route("/api/stats/families")
    @login_required
    def api_families():
        return jsonify(family_comparison())

    @app.route("/api/stats/recurring")
    @login_required
    def api_recurring():
        return jsonify(recurring_behavior())

    @app.route("/api/stats/realtime")
    @login_required
    def api_realtime():
        window = safe_int(request.args.get("window", 300), default=300, min_value=30, max_value=3600)
        return jsonify(realtime_activity(window_seconds=window))

    @app.route("/api/stats/fingerprinting")
    @login_required
    def api_fingerprinting():
        limit = safe_int(request.args.get("limit", 300), default=300, min_value=1, max_value=2000)
        days = safe_int(request.args.get("days", 30), default=30, min_value=1, max_value=365)
        filters = _parse_fingerprinting_filters(request.args)
        scoring = _fingerprinting_scoring_config()
        return jsonify(
            behavioural_fingerprinting(
                limit=limit,
                days=days,
                scoring=scoring,
                filters=filters,
            )
        )

    @app.route("/api/stats/sessions")
    @login_required
    def api_sessions_v3():
        day = (request.args.get("day") or "").strip() or None
        limit = safe_int(request.args.get("limit", 2000), default=2000, min_value=1, max_value=100000)
        sessions = build_sessions(
            start_iso=_day_start_iso(day) if day else None,
            end_iso=_day_end_iso(day) if day else None,
            limit=limit,
        )
        return jsonify({"day": day, "count": len(sessions), "sessions": sessions})

    @app.route("/api/stats/kpi-v3")
    @login_required
    def api_kpi_v3():
        day = (request.args.get("day") or "").strip() or None
        return jsonify(daily_kpi_v3(day_utc=day))

    @app.route("/api/stats/drift")
    @login_required
    def api_drift_v3():
        recent_days = safe_int(request.args.get("recent_days", 7), default=7, min_value=1, max_value=90)
        baseline_days = safe_int(
            request.args.get("baseline_days", 30), default=30, min_value=3, max_value=365
        )
        return jsonify(detect_drift(window_days=recent_days, baseline_days=baseline_days))

    @app.route("/api/stats/anomalies")
    @login_required
    def api_anomalies_v3():
        window_minutes = safe_int(request.args.get("window_minutes", 60), default=60, min_value=5, max_value=1440)
        return jsonify(detect_anomalies(window_minutes=window_minutes))

    @app.route("/api/alerts/run", methods=["POST"])
    @login_required
    def api_alerts_run_v3():
        window_minutes = safe_int(request.args.get("window_minutes", 60), default=60, min_value=5, max_value=1440)
        return jsonify(run_alert_pipeline(window_minutes=window_minutes))

    @app.route("/api/export/ml-dataset/json")
    @login_required
    def api_export_ml_json():
        days = safe_int(request.args.get("days", 60), default=60, min_value=1, max_value=365)
        limit = safe_int(
            request.args.get("limit_sessions", 100000),
            default=100000,
            min_value=1,
            max_value=1000000,
        )
        dataset = build_ml_dataset(limit_sessions=limit, days=days)
        out = export_ml_dataset_json(current_app.config["EXPORT_DIR"], dataset)
        return send_file(out, as_attachment=True)

    @app.route("/api/export/ml-dataset/csv")
    @login_required
    def api_export_ml_csv():
        days = safe_int(request.args.get("days", 60), default=60, min_value=1, max_value=365)
        limit = safe_int(
            request.args.get("limit_sessions", 100000),
            default=100000,
            min_value=1,
            max_value=1000000,
        )
        dataset = build_ml_dataset(limit_sessions=limit, days=days)
        out = export_ml_dataset_csv(current_app.config["EXPORT_DIR"], dataset)
        return send_file(out, as_attachment=True)

    @app.route("/api/export/bot-ips/json")
    @login_required
    def api_export_bot_ips_json():
        mode = _safe_ip_mode(request.args.get("mode", "anonymized"))
        limit = safe_int(request.args.get("limit", 500000), default=500000, min_value=1, max_value=1000000)
        inventory = bot_ip_inventory(mode=mode, limit=limit)
        out = export_bot_ip_inventory_json(current_app.config["EXPORT_DIR"], inventory)
        return send_file(out, as_attachment=True)

    @app.route("/api/export/bot-ips/csv")
    @login_required
    def api_export_bot_ips_csv():
        mode = _safe_ip_mode(request.args.get("mode", "anonymized"))
        limit = safe_int(request.args.get("limit", 500000), default=500000, min_value=1, max_value=1000000)
        inventory = bot_ip_inventory(mode=mode, limit=limit)
        out = export_bot_ip_inventory_csv(current_app.config["EXPORT_DIR"], inventory)
        return send_file(out, as_attachment=True)

    @app.route("/api/fingerprinting/presets", methods=["GET"])
    @login_required
    def api_fingerprinting_presets_list():
        return jsonify({"presets": list_fingerprint_presets()})

    @app.route("/api/fingerprinting/presets", methods=["POST"])
    @login_required
    def api_fingerprinting_presets_upsert():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400

        raw_filters = payload.get("filters") if isinstance(payload.get("filters"), dict) else {}
        normalized_filters = _normalize_fingerprint_filters(raw_filters)
        upsert_fingerprint_preset(name=name, filters=normalized_filters)
        return jsonify({"ok": True, "name": name, "filters": normalized_filters})

    @app.route("/api/fingerprinting/presets/<int:preset_id>", methods=["DELETE"])
    @login_required
    def api_fingerprinting_presets_delete(preset_id):
        deleted = delete_fingerprint_preset(preset_id)
        return jsonify({"ok": bool(deleted), "deleted": deleted})

    @app.route("/api/fingerprinting/export/json", methods=["GET"])
    @login_required
    def api_fingerprinting_export_json():
        result = _fingerprinting_result_from_request()
        out = export_fingerprinting_json(current_app.config["EXPORT_DIR"], result)
        return send_file(out, as_attachment=True)

    @app.route("/api/fingerprinting/export/csv", methods=["GET"])
    @login_required
    def api_fingerprinting_export_csv():
        result = _fingerprinting_result_from_request()
        out = export_fingerprinting_csv(current_app.config["EXPORT_DIR"], result)
        return send_file(out, as_attachment=True)

    @app.route("/api/reports/daily", methods=["POST"])
    @login_required
    def api_generate_daily_report():
        out, report = generate_daily_report(app.config["REPORT_DIR"])
        return jsonify({"ok": True, "file": str(out), "report": report})

    @app.route("/api/reports/daily-archive", methods=["POST"])
    @login_required
    def api_generate_daily_archive():
        days = safe_int(request.args.get("days", 7), default=7, min_value=1, max_value=365)
        zip_path, files = export_daily_reports_zip(app.config["REPORT_DIR"], days=days)
        return jsonify(
            {
                "ok": True,
                "zip_file": str(zip_path),
                "days": days,
                "generated_reports": [str(f) for f in files],
            }
        )

    @app.route("/export/json")
    @login_required
    def export_data_json():
        out = export_json(app.config["EXPORT_DIR"])
        return send_file(out, as_attachment=True)

    @app.route("/export/csv")
    @login_required
    def export_data_csv():
        out = export_csv(app.config["EXPORT_DIR"])
        return send_file(out, as_attachment=True)

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.route("/owner/mark")
    def owner_mark():
        token = (request.args.get("token") or "").strip()
        expected = current_app.config.get("OWNER_COOKIE_TOKEN") or ""
        if not expected or token != expected:
            return make_response("forbidden", 403)
        resp = make_response("ok")
        resp.set_cookie(
            current_app.config.get("OWNER_COOKIE_NAME", "hp_owner"),
            expected,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="Lax",
        )
        return resp

    return app


def _configure_logging(app):
    handler = RotatingFileHandler(
        filename="logs/app.log",
        maxBytes=app.config["LOG_MAX_BYTES"],
        backupCount=app.config["LOG_BACKUP_COUNT"],
    )
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)


def _record_cap(name, value, metadata=None):
    if _is_owner_request():
        return
    ip_anon = anonymize_ip(request.headers.get("X-Forwarded-For", request.remote_addr or ""))
    key = make_visitor_key(ip_anon, request.user_agent.string)
    insert_capability_event(key, name, value, metadata)


def _log_request(response):
    if _is_owner_request():
        return
    start = getattr(request, "_start_time", None)
    processing_ms = ((time.perf_counter() - start) * 1000.0) if start else None

    ip_raw_header = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip_raw = (ip_raw_header or "").split(",")[0].strip()
    ip_anonymized = anonymize_ip(ip_raw)
    ua = request.headers.get("User-Agent", "")
    visitor_key = make_visitor_key(ip_anonymized, ua)
    scope = infer_network_scope(ip_raw)

    category = classify_user_agent(ua)
    payload = {
        "ts_utc": utc_now_iso(),
        "visitor_key": visitor_key,
        "ip_anonymized": ip_anonymized,
        "ip_raw": ip_raw if current_app.config.get("STORE_RAW_IP") else None,
        "network_scope": scope,
        "url": request.url,
        "path": request.path,
        "method": request.method,
        "user_agent": ua,
        "referer": request.headers.get("Referer"),
        "status_code": response.status_code,
        "request_headers": dict(request.headers),
        "response_headers": dict(response.headers),
        "processing_ms": round(processing_ms, 3) if processing_ms is not None else None,
        "cookies": request.cookies,
        "get_params": request.args.to_dict(flat=False),
        "post_params": _extract_post_params(),
        "category": category,
        "robots_consulted": request.path == "/robots.txt",
        "sitemap_consulted": request.path == "/sitemap.xml",
    }
    insert_request_log(payload)

    removed = prune_request_logs(max_rows=current_app.config["MAX_DB_REQUEST_ROWS"])
    if removed:
        current_app.logger.warning("pruned old request rows: %s", removed)


def _is_owner_request():
    cookie_name = current_app.config.get("OWNER_COOKIE_NAME", "hp_owner")
    token = current_app.config.get("OWNER_COOKIE_TOKEN") or ""
    if not token:
        return False
    return request.cookies.get(cookie_name) == token


def _extract_post_params():
    if request.method not in {"POST", "PUT", "PATCH"}:
        return {}
    if request.is_json:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            return payload
        return {"_json": payload}
    return request.form.to_dict(flat=False)


def _parse_fingerprinting_filters(args):
    filters = {
        "category": (args.get("category") or "").strip() or None,
        "strategy": (args.get("strategy") or "").strip() or None,
        "js_capable": _parse_bool_arg(args.get("js")),
        "cookies_capable": _parse_bool_arg(args.get("cookies")),
        "min_score": _parse_float_arg(args.get("min_score")),
        "max_score": _parse_float_arg(args.get("max_score")),
        "min_depth": _parse_int_arg(args.get("min_depth")),
        "min_rpm": _parse_float_arg(args.get("min_rpm")),
        "max_rpm": _parse_float_arg(args.get("max_rpm")),
    }
    return {k: v for k, v in filters.items() if v is not None}


def _normalize_fingerprint_filters(raw):
    source = raw if isinstance(raw, dict) else {}
    out = {
        "days": _parse_int_arg(source.get("days")),
        "category": (source.get("category") or "").strip() or None,
        "strategy": (source.get("strategy") or "").strip() or None,
        "min_score": _parse_float_arg(source.get("min_score")),
        "max_score": _parse_float_arg(source.get("max_score")),
        "min_depth": _parse_int_arg(source.get("min_depth")),
        "min_rpm": _parse_float_arg(source.get("min_rpm")),
        "max_rpm": _parse_float_arg(source.get("max_rpm")),
        "js": _normalize_bool_string(source.get("js")),
        "cookies": _normalize_bool_string(source.get("cookies")),
    }

    if out["category"] == "all":
        out["category"] = None
    if out["strategy"] == "all":
        out["strategy"] = None

    return {k: v for k, v in out.items() if v is not None}


def _fingerprinting_result_from_request():
    limit = safe_int(request.args.get("limit", 300), default=300, min_value=1, max_value=2000)
    days = safe_int(request.args.get("days", 30), default=30, min_value=1, max_value=365)
    filters = _parse_fingerprinting_filters(request.args)
    scoring = _fingerprinting_scoring_config()
    return behavioural_fingerprinting(limit=limit, days=days, scoring=scoring, filters=filters)


def _fingerprinting_scoring_config():
    return {
        "depth_target": max(1, int(current_app.config.get("FP_DEPTH_TARGET", 20))),
        "coverage_target": max(1, int(current_app.config.get("FP_COVERAGE_TARGET", 30))),
        "speed_fast_rpm": max(1, int(current_app.config.get("FP_SPEED_FAST_RPM", 80))),
        "depth_first_min_depth": max(1, int(current_app.config.get("FP_DEPTH_FIRST_MIN_DEPTH", 12))),
        "breadth_min_unique_pages": max(
            1, int(current_app.config.get("FP_BREADTH_MIN_UNIQUE_PAGES", 25))
        ),
        "breadth_max_depth": max(1, int(current_app.config.get("FP_BREADTH_MAX_DEPTH", 8))),
        "iterative_revisit_threshold": float(
            current_app.config.get("FP_ITERATIVE_REVISIT_THRESHOLD", 0.35)
        ),
        "revisit_target": float(current_app.config.get("FP_REVISIT_TARGET", 0.15)),
        "revisit_sensitivity": float(current_app.config.get("FP_REVISIT_SENSITIVITY", 40)),
        "pace_good_min_sec": float(current_app.config.get("FP_PACE_GOOD_MIN_SEC", 0.5)),
        "pace_good_max_sec": float(current_app.config.get("FP_PACE_GOOD_MAX_SEC", 8.0)),
        "weight_depth": float(current_app.config.get("FP_WEIGHT_DEPTH", 20)),
        "weight_coverage": float(current_app.config.get("FP_WEIGHT_COVERAGE", 20)),
        "weight_consult_robots": float(current_app.config.get("FP_WEIGHT_CONSULT_ROBOTS", 10)),
        "weight_respect_robots": float(current_app.config.get("FP_WEIGHT_RESPECT_ROBOTS", 10)),
        "weight_consult_sitemap": float(current_app.config.get("FP_WEIGHT_CONSULT_SITEMAP", 5)),
        "weight_js_capable": float(current_app.config.get("FP_WEIGHT_JS_CAPABLE", 20)),
        "weight_cookies_capable": float(current_app.config.get("FP_WEIGHT_COOKIES_CAPABLE", 10)),
        "weight_pace_good": float(current_app.config.get("FP_WEIGHT_PACE_GOOD", 15)),
        "weight_pace_too_fast": float(current_app.config.get("FP_WEIGHT_PACE_TOO_FAST", 5)),
        "weight_pace_slow": float(current_app.config.get("FP_WEIGHT_PACE_SLOW", 10)),
        "weight_pace_neutral": float(current_app.config.get("FP_WEIGHT_PACE_NEUTRAL", 8)),
        "weight_revisit": float(current_app.config.get("FP_WEIGHT_REVISIT", 10)),
    }


def _parse_bool_arg(value):
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    return None


def _normalize_bool_string(value):
    parsed = _parse_bool_arg(value)
    if parsed is True:
        return "true"
    if parsed is False:
        return "false"
    return None


def _parse_int_arg(value):
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_float_arg(value):
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_ip_mode(value):
    normalized = str(value or "").strip().lower()
    if normalized == "raw":
        return "raw"
    return "anonymized"


def _day_start_iso(day):
    dt = _to_day_dt(day)
    return dt.isoformat()


def _day_end_iso(day):
    dt = _to_day_dt(day)
    return (dt + timedelta(days=1)).isoformat()


def _to_day_dt(day):
    return datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)


