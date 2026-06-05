# Schema SQLite

## Table `requests`

- `id` INTEGER PK
- `ts_utc` TEXT
- `visitor_key` TEXT
- `ip_anonymized` TEXT
- `url` TEXT
- `path` TEXT
- `method` TEXT
- `user_agent` TEXT
- `referer` TEXT
- `status_code` INTEGER
- `request_headers` TEXT (JSON)
- `response_headers` TEXT (JSON)
- `processing_ms` REAL
- `cookies` TEXT (JSON)
- `get_params` TEXT (JSON)
- `post_params` TEXT (JSON)
- `category` TEXT
- `robots_consulted` INTEGER
- `sitemap_consulted` INTEGER

## Table `capability_events`

- `id` INTEGER PK
- `ts_utc` TEXT
- `visitor_key` TEXT
- `event_name` TEXT
- `event_value` TEXT
- `metadata` TEXT (JSON)

## Table `daily_reports`

- `id` INTEGER PK
- `day_utc` TEXT UNIQUE
- `generated_at_utc` TEXT
- `content_json` TEXT (JSON)
