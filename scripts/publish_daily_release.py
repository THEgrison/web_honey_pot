from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None

from honeypot.analytics import export_daily_reports_zip
from honeypot.app import create_app


REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and publish a dated GitHub release.")
    parser.add_argument("--days", type=int, default=30, help="Number of days to include in the zip archive.")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repository in owner/name format. Defaults to GITHUB_REPOSITORY.",
    )
    parser.add_argument(
        "--token-env",
        default=os.environ.get("GITHUB_TOKEN_ENV", "RELEASE_TOKEN"),
        help="Environment variable containing the GitHub token.",
    )
    parser.add_argument(
        "--asset-name",
        default="",
        help="Optional asset name override. Defaults to the generated zip filename.",
    )
    parser.add_argument(
        "--body",
        default="Daily automated data export generated from crawler honeypot reports.",
        help="Release body text.",
    )
    return parser.parse_args()


def load_env_files() -> None:
    if load_dotenv is None:
        return
    for name in (".env", ".flaskenv"):
        candidate = REPO_ROOT / name
        if candidate.exists():
            load_dotenv(candidate, override=False)


def build_zip(days: int) -> Path:
    app = create_app()
    with app.app_context():
        zip_path, _files = export_daily_reports_zip(app.config["REPORT_DIR"], days=max(1, min(days, 365)))
    return Path(zip_path)


def github_request(method: str, url: str, token: str, data: bytes | None = None, content_type: str | None = None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "crawler-honeypot-release-script",
    }
    if content_type:
        headers["Content-Type"] = content_type

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
            return response.status, json.loads(payload.decode("utf-8")) if payload else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API error {exc.code} for {method} {url}: {body}") from exc


def get_release_by_tag(repo: str, tag: str, token: str):
    url = f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}"
    try:
        _status, data = github_request("GET", url, token)
        return data
    except RuntimeError as exc:
        if "GitHub API error 404" in str(exc):
            return None
        raise


def create_release(repo: str, tag: str, name: str, body: str, token: str):
    url = f"https://api.github.com/repos/{repo}/releases"
    payload = json.dumps(
        {
            "tag_name": tag,
            "name": name,
            "body": body,
            "draft": False,
            "prerelease": False,
        }
    ).encode("utf-8")
    _, data = github_request("POST", url, token, data=payload, content_type="application/json")
    return data


def update_release(repo: str, release_id: int, name: str, body: str, token: str):
    url = f"https://api.github.com/repos/{repo}/releases/{release_id}"
    payload = json.dumps({"name": name, "body": body, "draft": False, "prerelease": False}).encode("utf-8")
    _, data = github_request("PATCH", url, token, data=payload, content_type="application/json")
    return data


def delete_asset(repo: str, asset_id: int, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/releases/assets/{asset_id}"
    github_request("DELETE", url, token)


def upload_asset(upload_url: str, asset_path: Path, asset_name: str, token: str):
    base_url = upload_url.split("{")[0]
    query = urllib.parse.urlencode({"name": asset_name})
    url = f"{base_url}?{query}"
    with asset_path.open("rb") as handle:
        data = handle.read()
    _, payload = github_request("POST", url, token, data=data, content_type="application/zip")
    return payload


def release_date_tag() -> tuple[str, str]:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    date_value = now.strftime("%Y-%m-%d")
    return f"data-{date_value}", f"Data {date_value}"


def main() -> int:
    load_env_files()
    args = parse_args()

    if not args.repo:
        print("Missing repository. Set GITHUB_REPOSITORY or pass --repo owner/name.", file=sys.stderr)
        return 2

    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print(f"Missing token. Set {args.token_env} in the environment.", file=sys.stderr)
        return 2

    zip_path = build_zip(args.days)
    if not zip_path.exists():
        print(f"Archive not found: {zip_path}", file=sys.stderr)
        return 1

    tag, title = release_date_tag()
    body = args.body
    asset_name = args.asset_name or zip_path.name

    existing = get_release_by_tag(args.repo, tag, token)
    if existing is None:
        release = create_release(args.repo, tag, title, body, token)
    else:
        release = update_release(args.repo, int(existing["id"]), title, body, token)

    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            delete_asset(args.repo, int(asset["id"]), token)

    uploaded = upload_asset(release["upload_url"], zip_path, asset_name, token)

    print(f"Release tag: {release['tag_name']}")
    print(f"Release title: {release['name']}")
    print(f"Asset uploaded: {uploaded.get('name', asset_name)}")
    print(f"Release URL: {release.get('html_url', '')}")
    print(f"Archive source: {zip_path}")
    print(f"SHA256: {hashlib.sha256(zip_path.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())