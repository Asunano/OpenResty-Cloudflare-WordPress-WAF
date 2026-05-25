# WAF Configuration Reference Guide

All configuration options are in `openresty-cloudflare-wp-waf.lua` under `local cfg = { ... }`. Changes take effect after `nginx -s reload`.

---

## Table of Contents

- [Redis Connection Config](#redis-connection-config)
- [Core Risk Control Thresholds](#core-risk-control-thresholds)
- [Ban Duration Config](#ban-duration-config)
- [Logged-in User Baseline](#logged-in-user-baseline)
- [Window & Rate Limiting](#window--rate-limiting)
- [Whitelist Config](#whitelist-config)
- [Global Auto Mode Switch](#global-auto-mode-switch)
- [Parameter Detection](#parameter-detection)
- [Lightweight Scoring](#lightweight-scoring)
- [CDN Origin Protection](#cdn-origin-protection)
- [Malicious Rules](#malicious-rules)
- [Path Traversal Detection](#path-traversal-detection)
- [Feature Switches](#feature-switches)
- [Status Endpoint Config](#status-endpoint-config)
- [Tuning Guide](#tuning-guide)

---

## Redis Connection Config

| Option | Default | Description |
|--------|---------|-------------|
| `redis_host` | `"127.0.0.1"` | Redis server address |
| `redis_port` | `6379` | Redis port |
| `redis_db` | `0` | Redis database number |
| `redis_pass` | `nil` | Redis password (set to `nil` if no auth) |
| `redis_connect_timeout_ms` | `30` | TCP connect timeout (ms), fast fail to avoid queueing |
| `redis_eval_timeout_ms` | `100` | eval/eval sha operation timeout (ms) |
| `redis_keepalive_ms` | `10000` | Connection pool keepalive (ms) |
| `redis_max_connections` | `1024` | Must ≤ Redis `maxclients` setting |
| `redis_keepalive_pool` | auto-calculated | Connections per worker, auto-allocated by worker count |
| `redis_max_failures` | `5` | Consecutive failures to trigger circuit breaker |
| `redis_circuit_breaker_ttl` | `60` | Max circuit breaker duration (s), step backoff ceiling |
| `redis_circuit_breaker_init_ttl` | `10` | Initial breaker duration (s), quick recovery from brief blips |
| `redis_probe_interval` | `3` | Background probe interval during breaker (s) |

### Auto Pool Calculation

```lua
-- Formula: max_connections × 80% ÷ worker_count
-- Example: 8 workers → 1024 × 0.8 ÷ 8 = 102 per worker
redis_keepalive_pool = calculate_redis_pool_size()
```

> **Note**: `redis_max_connections` must be ≤ Redis actual maxclients. Connection failures occur if exceeded.

---

## Core Risk Control Thresholds

| Option | Default | Description |
|--------|---------|-------------|
| `risk_ban_threshold` | `100` | Risk score triggers ban at this value |
| `rep_ban_threshold` | `20` | Reputation score below this triggers ban |
| `base_burst_10s` | `18` | Base burst request limit per 10s |
| `base_slow_60s` | `12` | Base slow request limit per 60s |
| `score_ttl` | `1200` | Risk/reputation score expiry (s) |
| `risk_decay_ratio` | `0.03` | Natural risk decay per cycle (3%) |

---

## Ban Duration Config

| Option | Default | Description |
|--------|---------|-------------|
| `ban_soft` | `900` (15 min) | Light ban duration |
| `ban_mid` | `3600` (1 hour) | Medium ban duration |
| `ban_hard` | `86400` (24 hours) | Heavy ban duration |
| `local_ban_cache_ttl` | `300` (5 min) | Local shared memory ban cache TTL |

---

## Logged-in User Baseline

Logged-in users are no longer fully exempt—they undergo lightweight security checks:

| Option | Default | Description |
|--------|---------|-------------|
| `logged_user_enable` | `true` | Enable logged-in user tiered protection |
| `logged_user_post_burst_limit` | `60` | Logged-in user POST rate limit (/60s) |
| `logged_user_query_hard_limit` | `4000` | Logged-in user query length hard limit |
| `logged_user_rce_only` | `true` | Only check RCE patterns, skip SQLi/XSS |
| `logged_user_wp_asset_burst_10s` | `40` | WP admin asset 10s window max requests |
| `logged_user_wp_asset_slow_60s` | `180` | WP admin asset 60s window max requests |

> When `logged_user_rce_only = true`, parameter checking only scans RCE patterns for logged-in users, skipping SQLi and XSS (RCE is the most critical threat vector).

---

## Window & Rate Limiting

| Option | Default | Description |
|--------|---------|-------------|
| `seen_ttl` | `300` | URI visit record window (s) |
| `burst_ttl` | `10` | Burst rate window (s) |
| `slow_ttl` | `60` | Slow rate window (s) |
| `miss_window_ttl` | `60` | CDN MISS event window (s) |
| `miss_window_limit` | `8` | Trigger penalty if MISS exceeds this in 60s |
| `bypass_window_ttl` | `60` | CDN BYPASS event window (s) |
| `bypass_window_limit` | `30` | Trigger penalty if BYPASS exceeds this in 60s |

> **Why MISS threshold is lower than BYPASS**: MISS is normal for first visits; BYPASS indicates active cache evasion and is more suspicious.

---

## Whitelist Config

| Option | Default | Description |
|--------|---------|-------------|
| `whitelist_refresh_interval` | `300` | Auto-refresh interval for whitelist file (s) |
| `local_allow_file` | `"/www/server/nginx/lua/waf_whitelist.txt"` | IP whitelist file path |

Whitelist file format (one IP or CIDR per line):

```
127.0.0.1
10.0.0.0/8
192.168.1.0/24
172.16.0.0/12
```

---

## Global Auto Mode Switch

WAF has 4 global modes: **Normal(0) → Defend(1) → Attack(2) → Protection(3)**. Auto-switching is based on global counters (MISS/BYPASS/entropy).

| Option | Default | Description |
|--------|---------|-------------|
| `global_counter_ttl` | `10` | Global counter window (s) |
| `global_attack_miss_threshold` | `5` | MISS threshold to trigger attack mode |
| `global_attack_bypass_threshold` | `3` | BYPASS threshold to trigger attack mode |
| `global_attack_entropy_threshold` | `5` | Entropy threshold to trigger attack mode |
| `global_origin_miss_threshold` | `10` | MISS threshold to trigger origin protection |
| `global_origin_bypass_threshold` | `6` | BYPASS threshold to trigger origin protection |
| `global_origin_entropy_threshold` | `8` | Entropy threshold to trigger origin protection |
| `attack_mode_ttl` | `90` | Attack mode duration (s) |
| `origin_protect_ttl` | `60` | Origin protection mode duration (s) |

> **Hysteresis**: Mode 3 exit threshold = entry threshold × 0.7, preventing oscillation at boundary values.

---

## Parameter Detection

| Option | Default | Description |
|--------|---------|-------------|
| `query_entropy_args_soft_len` | `48` | Soft detection at this total args length |
| `query_entropy_args_hard_len` | `96` | Hard block at this total args length |
| `query_entropy_trigger_score` | `2` | Trigger Redis deep inspection at this entropy score |
| `query_entropy_value_soft_len` | `12` | Soft detection at this single value length |
| `query_entropy_token_soft` | `4` | Soft detection at this token count |
| `query_entropy_ratio_threshold` | `0.72` | Entropy threshold (0-1), above = suspicious |
| `html_query_max_len` | `128` | HTML query length limit in normal mode |
| `attack_html_query_max_len` | `64` | HTML query length limit in attack mode |
| `origin_html_query_max_len` | `32` | HTML query length limit in origin protection mode |
| `global_query_hard_limit` | `1024` | Global query length hard limit (all modes) |

---

## Lightweight Scoring

Phase 2 uses fast scoring to decide whether to enter Redis deep inspection:

| Option | Default | Description |
|--------|---------|-------------|
| `normal_light_score_threshold` | `8` | Score threshold to trigger Redis in normal mode |
| `light_score_bypass` | `4` | Points added for cache bypass signal |
| `light_score_entropy` | `4` | Points added for high entropy |
| `light_score_sensitive` | `4` | Points added for sensitive paths (e.g., /wp-admin) |
| `light_score_post_no_referer` | `3` | Points added for POST without Referer |
| `light_score_html_cookie_referer` | `-2` | Points deducted for HTML request with Cookie+Referer |
| `light_score_homepage` | `-1` | Points deducted for homepage request |
| `miss_bump_score` | `15` | Points added in feedback phase for MISS event |
| `bypass_bump_score` | `30` | Points added in feedback phase for BYPASS event |

> `light_score_html_cookie_referer` and `light_score_homepage` are negative scores, reducing false positives for normal users.

---

## CDN Origin Protection

| Option | Default | Description |
|--------|---------|-------------|
| `bypass_limit_per_ip_60s` | `15` | Max BYPASS events per IP in 60s |
| `global_req_flood_threshold` | `5000` | Global request flood threshold per 10s |
| `bypass_block_immediately` | `true` | Immediately block cache bypass signals (with first-visit exemption) |
| `cluster_ttl` | `300` | Cluster attack detection time window (s) |
| `cluster_threshold` | `6` | Cluster attack trigger threshold (unique URI/IP count) |
| `cluster_penalty` | `20` | Cluster attack penalty score |
| `enable_waf_cache_headers` | `true` | Whether WAF adds Cache-Control response headers |

`allowed_http_methods` table:

```lua
allowed_http_methods = {
    GET = true, HEAD = true, POST = true,
    OPTIONS = true, PUT = true, DELETE = true, PATCH = true,
}
```

> Non-whitelisted methods (TRACE, CONNECT, etc.) return 405 immediately.

---

## Malicious Rules

### Suspicious UA Blacklist (`malicious_uas`)

Case-insensitive, prefix matching. Used for scoring only, NOT hard blocking.

Defaults include: curl, wget, python-requests, scrapy, okhttp, phantomjs, selenium, nmap, sqlmap, nikto, burp, gobuster, ffuf, and other common scanners/tools.

### Malicious Parameter Keywords

Grouped by attack type, supporting context-aware dynamic detection group selection:

**Group 1 — RCE/Code Injection (`malicious_rce`)**: Applied to all requests.
```
shell, cmd, eval(, system(, exec(, phpinfo, passthru,
popen, proc_open, assert(, file_get_contents, include(
```

**Group 2 — SQL Injection (`malicious_sqli`)**: Only checked when args contain SQL character patterns (`'`, `;`, `@`), skipping ~80% clean traffic.
```
xp_cmdshell, sp_configure, union select, sleep(, benchmark(,
@@, char(, concat(, cast(, convert(
```

**Group 3 — XSS (`malicious_xss`)**: Only checked for HTML endpoints, skipped for API/static assets.
```
alert(, script>, onload=, onerror=, onclick=,
javascript:, vbscript:, data:text, base64,
```

### Regex Safety

| Option | Default | Description |
|--------|---------|-------------|
| `malicious_params_regex_max_len` | `1024` | Input length hard cap for detection, prevents ReDoS backtracking |
| `malicious_params_min_len` | `8` | Minimum args length gate, skip if shorter |

---

## Path Traversal Detection

| Option | Default | Description |
|--------|---------|-------------|
| `path_traversal_signals` | `{ "../", "./", "//", "\\", "%00", "%0a", "%0d", "%09" }` | Path traversal detection keywords |

> Note: Semicolon `;` removed from the list to avoid false positives on normal REST API calls and semicolon-separated params.

---

## Feature Switches

| Option | Default | Description |
|--------|---------|-------------|
| `block_xmlrpc` | `true` | Block XMLRPC requests |
| `block_empty_cookie` | `true` | Block HTML requests with empty Cookie |
| `block_empty_referer` | `true` | Block POST requests with empty Referer |
| `block_malicious_params` | `true` | Enable malicious parameter detection |
| `block_path_traversal` | `true` | Enable path traversal attack detection |
| `enable_local_rate_limit` | `true` | Enable local rate limiting |
| `log_level` | `"info"` | Log level: `debug` / `info` / `warn` / `error` |
| `enable_debug_log` | `false` | Enable verbose debug logging (avoid in high-traffic) |
| `force_block_log_error` | `true` | Force all block logs to ERROR level |

---

## Status Endpoint Config

| Option | Default | Description |
|--------|---------|-------------|
| `status_endpoint_enabled` | `false` | Enable runtime status HTTP endpoint |
| `status_endpoint_path` | `"/waf-status"` | Endpoint access path |
| `status_endpoint_allowed_ips` | `{"127.0.0.1"}` | Allowed IP list |
| `status_metrics_ttl_days` | `7` | Independent Redis storage TTL for status metrics (days), `0` = permanent |

When enabled, `GET /waf-status` returns a plain-text runtime status report (including independently stored request/block statistics). Non-whitelisted IPs receive 404.

> `status_metrics_ttl_days` controls metrics stored in Redis under the independent `wf:status:*` keyspace, unaffected by `global_counter_ttl`. Only active when `status_endpoint_enabled = true`.

---

## Tuning Guide

### Reducing False Positives

```lua
-- Raise thresholds for normal users
risk_ban_threshold = 150
base_burst_10s = 30
base_slow_60s = 20

-- Reduce scoring aggressiveness
light_score_entropy = 2
normal_light_score_threshold = 10

-- Disable immediate bypass blocking
bypass_block_immediately = false
```

### Increasing Security

```lua
-- Lower thresholds for more aggressive blocking
risk_ban_threshold = 70
rep_ban_threshold = 30

-- Longer ban durations
ban_soft = 1800      -- 30 minutes
ban_mid = 7200       -- 2 hours
ban_hard = 172800    -- 48 hours

-- Stricter global mode switching
global_origin_miss_threshold = 6
```

### Non-Cloudflare Environments

```lua
bypass_block_immediately = false   -- Disable immediate blocking
light_score_bypass = 0             -- Zero bypass score without CF trust
```
