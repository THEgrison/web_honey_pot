import re


PATTERNS = {
    "search_engine": [
        r"googlebot",
        r"bingbot",
        r"yandex",
        r"duckduckbot",
        r"baiduspider",
    ],
    "ai_bot": [
        r"gptbot",
        r"claudebot",
        r"ccbot",
        r"perplexity",
        r"amazonbot",
        r"bytespider",
    ],
    "scraper": [
        r"scrapy",
        r"python-requests",
        r"httpclient",
        r"curl",
        r"wget",
        r"aiohttp",
    ],
    "human_browser": [
        r"mozilla/5\.0",
        r"safari",
        r"chrome",
        r"firefox",
        r"edge",
    ],
}


def classify_user_agent(user_agent):
    if not user_agent:
        return "unknown_bot"

    ua = user_agent.lower()

    for pattern in PATTERNS["search_engine"]:
        if re.search(pattern, ua):
            return "search_engine"

    for pattern in PATTERNS["ai_bot"]:
        if re.search(pattern, ua):
            return "ai_bot"

    for pattern in PATTERNS["scraper"]:
        if re.search(pattern, ua):
            return "scraper"

    for pattern in PATTERNS["human_browser"]:
        if re.search(pattern, ua) and "bot" not in ua:
            return "human_browser"

    if "bot" in ua or "spider" in ua or "crawler" in ua:
        return "unknown_bot"

    return "human_browser"
