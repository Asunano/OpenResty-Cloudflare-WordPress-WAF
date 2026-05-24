# OpenResty Cloudflare WordPress WAF

[![OpenResty](https://img.shields.io/badge/OpenResty-%E2%89%A5%201.21.4-blue?logo=openresty)](https://openresty.org/)
[![Redis](https://img.shields.io/badge/Redis-%E2%89%A5%207.0-red?logo=redis)](https://redis.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

A high-performance, multi-layer Web Application Firewall (WAF) for WordPress sites running on OpenResty with Cloudflare CDN. Features adaptive defense mechanisms, Redis-powered risk scoring, intelligent rate limiting, and automatic global mode switching.

> **Note:** Code and configuration comments are primarily in Chinese. This document provides full English documentation. For Chinese, see [README.md](README.md).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [IP Whitelist](#ip-whitelist)
- [Monitoring & Logging](#monitoring--logging)
- [Testing & Verification Guide](#testing--verification-guide)
- [Troubleshooting](#troubleshooting)
- [Version Compatibility](#version-compatibility)
- [Performance Tuning](#performance-tuning)
- [Glossary](#glossary)
- [FAQ](#faq)
- [Security Design Notes](#security-design-notes)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Quick Start

### 1. Prerequisites

```bash
# Install dependencies (Debian/Ubuntu example)
apt update && apt install -y openresty redis-server

# Verify installation
openresty -v
redis-cli --version
```

### 2. Deploy WAF

```bash
# Download script
wget https://raw.githubusercontent.com/Asunano/OpenResty-Cloudflare-WordPress-WAF/main/openresty-cloudflare-wp-waf.lua -P /www/server/nginx/lua/

# Create whitelist file
touch /www/server/nginx/lua/waf_whitelist.txt
```

### 3. Configure Nginx

Edit your site configuration file and add the following:

```nginx
# Add in http block (global configuration)
lua_shared_dict wf_ban_cache  16m;
lua_shared_dict wf_meta_cache 16m;
init_worker_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;

# Add in server block (site-level configuration)
server {
    listen 80;
    server_name your-domain.com;

    # WAF core configuration
    access_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;
    log_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;

    # Your existing configuration
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. Restart Services

```bash
nginx -t && nginx -s reload
systemctl restart redis-server
```

### 5. Verify Installation

```bash
# Test SQL injection blocking
curl "http://your-domain.com/?id=1' union select 1,2,3--"
# Should return 403 Forbidden
```

---

## Architecture Overview

```
                   Client / Attacker
                         │
                   Cloudflare CDN
            (cf-ray, cf-connecting-ip, etc.)
                         │
               OpenResty (Nginx + Lua)
  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐
  │ init_worker  │  │    access    │  │     log       │
  │ - Load rules │  │  - Phase 1-4 │  │ - Cache       │
  │ - Init Redis │  │  - Scoring   │  │   Feedback    │
  └─────────────┘  └──────┬───────┘  └───────┬───────┘
                          │                   │
                 ┌────────▼───────────────────▼──┐
                 │   lua_shared_dict (Memory)     │
                 │   wf_ban_cache / wf_meta_cache │
                 └────────┬───────────────────────┘
                          │
                    Redis (Risk Scoring)
  - Risk/Reputation Scores  - Burst/Slow Limits
  - Cluster Detection       - Daily Statistics
  - Distributed Locking     - Path Whitelist
```

---

## How It Works

### Execution Model: Three-Phase Lifecycle

The WAF script automatically switches between two execution modes and covers the full request lifecycle via three Nginx phases:

```
┌──────────────────────────────────────────────────────┐
│         Single-load mode (require / module)           │
│  require("openresty-cloudflare-wp-waf") → returns _M  │
│  Loaded once; call _M.xxx() manually per phase        │
├──────────────────────────────────────────────────────┤
│         Multi-phase mode (file-based)                 │
│  Nginx re-reads script per phase → auto-dispatch      │
│  based on ngx.get_phase()                             │
└──────────────────────────────────────────────────────┘
```

| Nginx Phase | Function | When | What It Does |
|------------|----------|------|--------------|
| `init_worker` | `_M.init_worker()` | Once per worker process startup | Pre-compile all regex, load IP whitelist from file, verify shared memory state |
| `access` | `_M.access()` | **Every HTTP request** | Core WAF logic: 4-phase progressive inspection, risk scoring, blocking decisions |
| `log` | `_M.log()` | After response is sent | Async analysis via `ngx.timer.at` of cache origin behavior, feedback scoring, smart banning |

### Access Phase: Progressive 4-Phase Inspection

The `access` phase is the core of the WAF, using increasingly expensive checks to ensure 90%+ of legitimate traffic passes through the first two phases quickly:

**Phase 1 — Base Exemption & Fast Path** (minimal overhead, memory-only)

Uses a "whitelist-first" strategy in priority order:

1. **HTTP method whitelist**: Only `GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS` allowed, others → 405
2. **IP whitelist exemption**: Matches against local file (with CIDR support) or Redis dynamic whitelist → pass with logging
3. **System path exemption**: `wp-cron.php` (localhost/private IP → pass; external → 1 req/10s rate limit), health checks, robots.txt
4. **Logged-in user baseline check**: No longer fully exempt. Lightweight checks only (RCE, path traversal, extreme UA, long queries). Cookie must match WordPress signature format `user|expiry|token|hmac`
5. **Fast Path release**: Static assets (css/js/images/fonts) → 30-day strong cache; core pages → 1-hour cache; both with `X-Cache-Status` header

> ~90% of legitimate traffic ends here without further inspection.

**Phase 2 — In-Memory Hard Block** (1-2 shared memory operations, zero Redis IO)

Blocks clear attack patterns directly at the OpenResty layer:

| Check | Method | Optimization |
|-------|--------|-------------|
| Path traversal | Recursive URL decode (max 20 layers) + pattern matching | Requests without `%` encoding skip recheck |
| Malicious params | Pre-compiled regex (RCE/SQLi/XSS grouped) | Requests without SQL literals (~80%) skip SQLi regex; params < 8 chars skipped |
| Query too long | `#args` length hard limit | O(1) string length check |
| Suspicious UA | Substring matching against scanner fingerprints | Log-only, no hard block |
| Global flood | `lua_shared_dict` global counter | 10s window, auto-escalates to origin protect mode |
| Local rate limiting | IP + IP:URI dual-dimension counting | 10s/60s windows, threshold = base × 2 |
| Range header | Block Range on non-static assets | Prevents resource exhaustion from large file ranges |
| Bypass immediate block | Detect nocache params/headers | Non-static with bypass signal → 444 immediately |

**Phase 3 — Context-Aware Smart Block** (2-3 overhead, requires request context parsing)

Jointly evaluates multiple request characteristics for more intelligent decisions:

- **Origin bypass progressive response**: Tracks per-IP bypass count with three-stage response → `4-8 times` force cache → `9-15 times` warning → `>15 times` return 429
- **Empty cookie multi-dimensional scoring**: Combines CF trust score + UA browser characteristics + URI entropy + cache state + frequency counter for a 0-10+ suspicion score. ≥7 blocks, ≥4 warns
- **Empty referer detection**: POST requests only; exempts API/JSON/CORS/static paths

**Phase 4 — Redis Deep Inspection** (4+ overhead, Redis round-trip + Lua atomic execution)

Only requests that pass the first three phases with `quick_score > 0` (have suspicious signals) enter this phase. The core is an embedded Redis Lua script (`ACCESS_SCRIPT`) that executes atomically on the Redis server:

```
┌─ Input Flags ─────────────────────────────────────────┐
│ risk_add    rep_penalty  rep_bonus                    │
│ has_cookie  has_referer  is_html  is_api  is_auth     │
│ is_static   is_bypass    ua_suspicious  is_entropy     │
│ is_cluster                                              │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ Redis Lua Script (Atomic) ──────────────────────────┐
│                                                         │
│  1. Read current risk / rep scores                      │
│  2. Record URI to visited set, count unique visits      │
│  3. Dynamically calculate rate limits based on rep:     │
│     burst_limit = burst_base + floor((rep-50)/4)         │
│     slow_limit  = slow_base  + floor((rep-50)/6)         │
│  4. INCR burst/slow counters, set window expiry on 1st  │
│  5. Natural decay: risk = risk - floor(risk × 0.03)    │
│  6. Accumulate risk (entropy +15, cluster +20, etc.)    │
│  7. Human/bot behavior modeling                         │
│  8. Ban based on total score + reputation               │
│                                                         │
└───────────────────────────────────────────────────────┘
```

**Human/Bot Behavior Modeling**: Rather than simply treating all cookieless requests as bots, the WAF uses multi-dimensional features:

- **Human signals**: Has Cookie (+1), Has Referer (+1), HTML page with both + ≤15 unique URIs (+1)
- **Bot signals**: Suspicious UA (+1), Auth path without Cookie (+2), API without Cookie + too many unique URIs (+1), Static without Cookie + >30 unique URIs (+1), Cache bypass (+1), POST without Referer (+1)

When `bot_score ≥ 2`, penalty is triggered: rep lowered, risk raised.

**Adaptive Rate Thresholds**: Higher reputation = more lenient rate limits (trusted users get larger request quotas); lower reputation = tighter limits.

### Log Phase: Async Feedback & Smart Banning

The `log` phase executes after the response is sent, using `ngx.timer.at(0, callback)` to create **zero-delay async timers** that never block user responses:

1. Check `upstream_cache_status`: `HIT` → skip; `MISS/BYPASS/EXPIRED/STALE` → process
2. Async execute `FEEDBACK_SCRIPT` (Redis Lua), count MISS/BYPASS, add risk score when thresholds exceeded
3. Suspicious bot detection: UA claims to be a bot but behaves abnormally → flag + ban
4. Origin abuse ban triggers: miss exceed ×2 / bypass exceed ×2 / both exceed simultaneously
5. Sync ban to local shared memory cache for subsequent requests even if Redis is down

### Circuit Breaker

```
Normal ──5 consecutive──▶ Open (10s)
         failures           │
                  ┌─────────┴──────────┐
                  ▼                    ▼
          Background probe        Local shared memory
          (every 3s)              fallback:
                  │                ├─ Local ban cache hit
          Recovery?                ├─ quick_score ≥ 35 block
                  │                └─ Outage > 30s → stricter
        ┌──No──┴──Yes──┐                thresholds
        ▼              ▼
   Backoff (20s→60s)  Close, resume normal
```

- **Dual-ladder timeout**: connect 30ms (fast fail, avoid queuing), eval 100ms (gives Redis ample compute time)
- **Staggered backoff**: 10s → 20s → 60s, preventing oscillation
- **Safe degradation**: Local shared memory continues providing basic protection even during Redis outages

### Adaptive Sampling

To protect Redis under high load, the WAF dynamically adjusts Phase 4 sampling rates:

| Scenario | Sampling Strategy |
|----------|------------------|
| Risk score ≥ 30 (high risk) | Always 100% |
| Risk score 15-29 (medium risk) | Minimum 30% even under high load |
| Low risk + low load | Default per-mode (normal 10% → origin protect 100%) |
| Low risk + high load | Reduced to 25% of base rate |

### Key Performance Techniques

| Technique | Description | Impact |
|-----------|------------|--------|
| Pre-compiled regex | Group-compiled by attack type at `init_worker` | Zero per-request compilation |
| Entropy lookup table | Pre-computed entropy values for bytes 0-255 | O(1) replaces `math.log()` |
| Short-circuit optimization | SQL literal pre-scan → skip SQLi regex if no match | ~80% traffic skips most expensive regex |
| Param length gating | Params < 8 chars skip regex | Zero overhead for short params |
| Request-level cache | `ngx.ctx` caches bypass/malicious param results | No duplicate checks per request |
| Pass 2 skip | Requests without `%` encoding skip URL decode recheck | Zero extra overhead for normal requests |
| Unified header table | All header keys lowercased | Prevents case-mismatch false negatives |

---

## Key Features

### 1. Multi-Layer Protection (4-Phase Inspection)

Each request passes through up to 4 phases of increasingly expensive inspection:

| Phase | Name | Cost | Description |
|-------|------|------|-------------|
| 1 | **Base Exemption & Fast Path** | 0-1 | Whitelist IPs, core paths, logged-in users, static assets. ~90% of requests end here. |
| 2 | **In-Memory Hard Block** | 1-2 | Path traversal, malicious params, UA detection, global flood detection, rate limiting |
| 3 | **Context-Aware Smart Block** | 2-3 | Empty cookie analysis, empty referer, XMLRPC, POST body, file upload detection |
| 4 | **Deep Redis Inspection** | 4+ | Entropy scoring, Redis-based risk/reputation scoring, cluster attack detection |

### 2. Cloudflare Integration

- Validates Cloudflare headers (`cf-ray`, `cf-connecting-ip`, `cf-ipcountry`, `cf-visitor`) for trust scoring
- Detects cache bypass signals (nocache parameters, Cache-Control headers, X-* bypass headers)
- Distinguishes between normal miss (first visit) and malicious bypass behavior
- Progressive bypass response: force cache → short cache + warning → block
- WAF-managed Cache-Control headers

### 3. WordPress-Optimized Security

| Feature | Description |
|---------|-------------|
| Logged-in user baseline check | Lightweight checks instead of full exemption (RCE, path traversal, UA length, query length). Cookie must have WordPress signature format (`user\|expiry\|token\|hmac`). |
| WP admin asset rate limiting | Prevents admin account abuse on load-scripts/load-styles/admin-ajax. Limits logged-in users to 40 req/10s |
| wp-cron.php protection | Allows localhost/private IPs freely, rate-limits external IPs to 1 req/10s |
| XMLRPC blocking | Mitigates brute force and DDoS via xmlrpc.php |
| wp-json/wp-sitemap whitelist | Uses original request URI (pre-rewrite) for matching. Properly handles WP REST API and sitemap |
| POST body protection | Size limit (1MB), Content-Type validation, malicious file upload detection |
| Archives path protection | GET/HEAD only, validated query parameters |

### 4. Redis-Powered Risk Scoring

Two Redis Lua scripts handle all scoring atomically:

**Access Script** — Evaluates every request that reaches the deep inspection phase:
- **Risk Score** (0-∞): Accumulates based on suspicious behavior
- **Reputation Score** (0-100): Starts at 100, decays with bad behavior, recovers with good behavior
- **Adaptive Limits**: Burst/Slow thresholds adjust dynamically based on reputation
- **Three-tier banning**: 15min / 1hr / 24hr based on severity

**Feedback Script** — Processes cache feedback in the log phase via `ngx.timer`:
- Detects excessive origin requests (miss/bypass abuse)
- Identifies suspicious bots (bot UA with excessive nocache behavior)
- Progressive banning for origin abuse

### 5. Automatic Global Mode Switching

The WAF automatically escalates and de-escalates between 4 protection modes based on global pressure signals:

| Mode | Level | Response | Criteria |
|------|-------|----------|----------|
| Normal | 0 | Standard inspection | Below all thresholds |
| Defend | 1 | Stricter HTML query limits | Elevated miss/bypass/entropy |
| Attack | 2 | Block bypass + high-entropy requests | Attack threshold exceeded |
| Origin Protect | 3 | Most restrictive (parameter validation, no-cookie blocking) | Origin threshold exceeded |

Pressure signals are tracked in `lua_shared_dict` with configurable TTL windows. De-escalation uses hysteresis (lower thresholds) to prevent flapping.

### 6. Redis Circuit Breaker

- **Stair-step backoff**: 10s → 20s → 60s on repeated failures
- **Background probe timer**: Automatically tests Redis connectivity and self-heals
- **Safe local degradation**: Continues basic protection via shared memory when Redis is down:
  - Local ban cache hits → block
  - High risk scores (≥35) → block locally
  - Extended outages (>30s) → stricter local thresholds
- **Dual-stage timeout**: connect 30ms (fast fail, no queueing), eval 100ms (ample time for Redis Lua computation)

### 7. Adaptive Sampling

To protect Redis under high load, the WAF dynamically adjusts its sampling rate:
- **Low load**: Default sampling rate per mode (10% normal → 100% origin protect)
- **High load**: Down to 25% of base rate for low-risk requests
- **High-risk (score ≥30)**: Always 100% sampled
- **Medium-risk (15-29)**: Minimum 30% sampling even under load

### 8. Distributed Locking

All critical operations use distributed locks with clock drift protection:
- Whitelist file refresh
- Redis data cleanup (24h interval)
- Circuit breaker reset
- Path whitelist reload from Redis

Locks include worker PID + timestamp for safe release verification. Values are matched before deletion to prevent cross-worker race conditions.

### 9. Comprehensive Detection

| Category | Detection Method |
|----------|-----------------|
| RCE/Code Injection | Compile-once regex grouped by attack type |
| SQL Injection | Pre-scan with SQL literal detection, then regex |
| XSS | Context-aware (HTML endpoints only) |
| Path Traversal | Recursive URL decode + pattern matching |
| Suspicious UA | Keyword matching with length/context awareness |
| Cache Bypass | Query params, headers, entropy, parameter count |
| Entropy Attack | O(1) table lookup for high-entropy query detection |
| Cluster Attack | Redis ZSET IP ↔ URI mapping with Lua script |
| DDoS Flood | Global shared memory counter with mode escalation |

### 10. Performance Optimizations

- **Pre-compiled regex**: Compiled once at worker init, grouped by attack type
- **Entropy lookup tables**: O(1) table lookups instead of `math.log()` calls
- **Short-circuit optimization**: Skip SQLi regex on requests without SQL literals (~80% of traffic)
- **Parameter length gating**: Skip regex on args shorter than 8 characters
- **Request-level caching**: `ngx.ctx` caching for bypass/malicious param detection within same request
- **Pass 2 skip**: Skip URL-decode re-check on requests without `%` encoding
- **Header table unified**: All lowercase keys to avoid case-mismatch issues

---

## Prerequisites

### Required Components

| Component | Recommended | Purpose |
|-----------|-------------|---------|
| OpenResty | ≥ 1.21.4 | LuaJIT-powered Nginx with full regex JIT support |
| Redis | ≥ 7.0 | Distributed risk scoring, Lua atomic scripts, locking, whitelist |
| Cloudflare | Any plan | CDN, cache, trusted headers |

### Required Nginx Configuration

```nginx
lua_shared_dict wf_ban_cache  16m;
lua_shared_dict wf_meta_cache 16m;

# Worker initialization
init_worker_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

# Access phase
server {
    # ... your server config ...

    access_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

    # Log phase (for cache feedback)
    log_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

    # Your proxy/config here
    location / {
        proxy_pass http://your_upstream;
    }
}
```

### Lua Module Import (Alternative)

```lua
local waf = require("openresty-cloudflare-wp-waf")

-- In init_worker_by_lua:
waf.init_worker()

-- In access_by_lua:
waf.access()

-- In log_by_lua:
waf.log()
```

---

## Configuration

All configuration is centralized in the `cfg` table and clearly marked:

```lua
local cfg = {
    -- ── Redis ──────────────────────────────────────────
    redis_host = "127.0.0.1",
    redis_port = 6379,
    redis_pass = nil,

    -- ── Thresholds ─────────────────────────────────────
    risk_ban_threshold = 100,     -- Risk score → ban
    rep_ban_threshold  = 20,      -- Reputation score → ban
    base_burst_10s     = 18,      -- Burst limit (10s window)
    base_slow_60s      = 12,      -- Slow limit (60s window)

    -- ── Ban Durations ──────────────────────────────────
    ban_soft = 900,    -- 15 minutes
    ban_mid  = 3600,   -- 1 hour
    ban_hard = 86400,  -- 24 hours

    -- ── Feature Toggles ────────────────────────────────
    block_xmlrpc            = true,
    block_malicious_params  = true,
    block_path_traversal    = true,
    enable_local_rate_limit = true,
    -- ... more settings ...
}
```

### Customizing Malicious Parameter Rules

Edit the `malicious_rce`, `malicious_sqli`, and `malicious_xss` tables to add or remove patterns:

```lua
malicious_rce = {
    "shell", "cmd", "eval(", "system(", "exec(", ...
},
malicious_sqli = {
    "xp_cmdshell", "union+select", "sleep(", ...
},
malicious_xss = {
    "alert(", "script>", "onload=", ...
},
```

### Customizing Malicious UA Detection

Edit the `malicious_uas` table. Note that certain commonly blocked UAs (like `go-http-client` and `headlesschrome`) have been intentionally excluded to avoid false positives with legitimate services.

---

## IP Whitelist

### File-based Whitelist

Create a file at the path specified by `cfg.local_allow_file` (default: `/www/server/nginx/lua/waf_whitelist.txt`):

```
# Single IPs
192.168.1.100
10.0.0.50

# CIDR ranges (requires bit library for full support)
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12

# 127.0.0.1 is always included by default
```

Whitelist is reloaded every `cfg.whitelist_refresh_interval` seconds, and only one worker performs the file I/O (distributed lock).

### Redis Dynamic Whitelist

Add whitelisted paths via Redis set:

```bash
redis-cli SADD "wf:wl:path" "/custom-whitelist-path"
redis-cli SADD "wf:wl:path" "/custom-prefix/*"
```

Paths ending with `*` are treated as prefix matches; all others are exact matches. The WAF includes default whitelisted paths for WordPress core files (`/wp-content/`, `/wp-includes/`, `/wp-json/`, `.well-known/`, etc.).

### Programmatic API

```lua
-- Add/remove whitelist paths
waf.add_whitelist_path("/api/public")
waf.remove_whitelist_path("/api/public")

-- Manual mode control
waf.enable_attack_mode(90)       -- Attack mode for 90 seconds
waf.enable_origin_protect(60)    -- Origin protect for 60 seconds
waf.clear_global_modes()         -- Return to normal mode

-- Get status
local status = waf.get_status()
-- Returns: { mode, whitelist_exact, whitelist_prefix, last_whitelist_reload }
```

---

## Monitoring & Logging

### Log Format

All logs include request IDs for correlation tracking:

```
[WAF] [WARN] [Rate Limited] (RATE_LIMITED) req_id=... ip=xxx uri=/path details...
[WAF] [ERROR] [Local Ban Cache Hit] (LOCAL_BAN_CACHE_HIT) req_id=... ip=xxx uri=/path score=120...
```

### Block Events (Logged at ERROR level when `force_block_log_error=true`)

| Event | Meaning | HTTP Status |
|-------|---------|-------------|
| `MALICIOUS_PARAM_BLOCKED` | Malicious parameter detected | 403 |
| `PATH_TRAVERSAL_BLOCKED` | Path traversal attack | 403 |
| `EMPTY_COOKIE_BLOCKED` | Empty cookie on HTML request | 403 |
| `EMPTY_REFERER_BLOCKED` | Empty referer on POST | 403 |
| `RATE_LIMITED` | Rate limit exceeded | 429 |
| `LOCAL_RATE_LIMIT_BLOCKED` | Local rate limit triggered | 429 |
| `XMLRPC_BLOCKED` | XMLRPC blocked | 403 |
| `BYPASS_IMMEDIATE_BLOCKED` | Cache bypass blocked immediately | 444 |
| `BYPASS_LIMIT_TRIGGERED` | Origin bypass limit triggered | 429 |
| `LOCAL_BAN_CACHE_HIT` | Local ban cache hit | 403 |
| `ORIGIN_PROTECT_BLOCKED` | Origin protect mode block | 444 |
| `POST_BODY_TOO_LARGE` | POST body exceeds 1MB | 413 |
| `INVALID_CONTENT_TYPE` | Invalid Content-Type | 415 |
| `MALICIOUS_FILE_UPLOAD` | Malicious file upload blocked | 403 |
| `CIRCUIT_BREAKER_BLOCKED` | Circuit breaker block | 503 |
| `ATTACK_MODE_BLOCKED` | Attack mode block | 444 |
| `DEFEND_MODE_BLOCKED` | Defend mode block | 403 |
| `WP_CRON_RATE_LIMITED` | WP-Cron rate limited | 429 |
| `LOGGED_USER_WP_ASSET_RATE_LIMITED` | Logged-in user WP asset rate limited | 429 |
| `ORIGIN_ABUSE_BANNED` | Origin abuse banned | 403 |
| `RANGE_HEADER_BLOCKED` | Range header blocked | 403 |
| `ARCHIVES_METHOD_BLOCKED` | Archives method blocked | 405 |
| `ARCHIVES_ARGS_BLOCKED` | Archives args blocked | 403 |
| `QUERY_TOO_LONG_BLOCKED` | Query string too long | 403 |
| `INVALID_METHOD` | Invalid HTTP method | 405 |
| `MALICIOUS_POST_BODY` | Malicious POST body blocked | 403 |
| `LOCAL_DEFENSE_HIGH_SCORE` | Local defense - high score block (Redis unavailable) | 403 |
| `LOCAL_DEFENSE_EXTENDED_OUTAGE` | Local defense - extended outage block (prolonged Redis downtime) | 403 |
| `IP_ALREADY_BANNED` | IP already banned (repeat offender) | 403 |
| `IP_BANNED_ACCESS` | IP banned at access phase | 403 |
| `IP_BANNED_FEEDBACK` | IP banned at log/feedback phase | 403 |
| `WHITELIST_BYPASS_BLOCKED` | Whitelist bypass blocked | 444 |

### Shared Memory Monitoring

The WAF automatically monitors `lua_shared_dict` usage and logs warnings at 80% capacity, critical alerts at 95%:

```
[WAF] [SHM_HIGH] wf_ban_cache usage=85.3% capacity=16777216 free=2460128 bytes — consider increasing lua_shared_dict
```

---

## Testing & Verification Guide

### 1. Basic Functionality Test

```bash
# Test normal request
curl -I http://your-domain.com/
# Should return 200 OK

# Test SQL injection blocking
curl -I "http://your-domain.com/?id=1' OR 1=1--"
# Should return 403 Forbidden

# Test XSS blocking
curl -I "http://your-domain.com/?q=<script>alert(1)</script>"
# Should return 403 Forbidden

# Test path traversal blocking
curl -I "http://your-domain.com/../../etc/passwd"
# Should return 403 Forbidden
```

### 2. Rate Limiting Test

```bash
# Send 20 rapid requests
for i in {1..20}; do curl -I http://your-domain.com/; done
# Requests 19-20 should return 429 Too Many Requests
```

### 3. Whitelist Test

```bash
# Add IP to whitelist
echo "192.168.1.100" >> /www/server/nginx/lua/waf_whitelist.txt
# Wait for auto-refresh or restart Nginx

# Send malicious request from whitelisted IP
curl -I "http://your-domain.com/?id=1' OR 1=1--"
# Should return 200 OK (whitelisted)
```

### 4. Redis Scoring Test

```bash
# Send multiple malicious requests
for i in {1..10}; do curl -I "http://your-domain.com/?id=1' OR 1=1--"; done

# Check risk score in Redis
redis-cli GET "wf:risk:YOUR_IP"
# Should return a value greater than 0
```

---

## Troubleshooting

### 1. WAF Not Working

- Check Nginx configuration syntax: `nginx -t`
- Verify `access_by_lua_file` and `log_by_lua_file` paths are correct
- Check Nginx error logs: `tail -f /www/server/nginx/logs/error.log`
- Ensure `lua_code_cache on;` (default)

### 2. Redis Connection Failed

- Check Redis service status: `systemctl status redis-server`
- Verify Redis port and password configuration
- Look for `REDIS_CONNECT_FAILED` errors in WAF logs
- Ensure firewall allows local port 6379 communication

### 3. False Positives

- Check Nginx error logs for block events and reasons
- Add the affected IP to the whitelist
- Adjust relevant thresholds (e.g., `bypass_window_limit`)
- Disable specific detection rules (e.g., `block_empty_cookie = false`)

### 4. Shared Memory Full

- Increase `lua_shared_dict` size (recommend 32m or 64m from 16m)
- Shorten `local_ban_cache_ttl` to reduce cache duration
- Look for `SHM_CRITICAL` alerts in logs

---

## Version Compatibility

| Component | Recommended | Minimum |
|-----------|------------|---------|
| OpenResty | ≥ 1.21.4 | 1.15.8 (requires `ngx.worker` API) |
| Redis | ≥ 7.0 | 6.0 (requires Lua script atomic execution) |
| Cloudflare | Any plan | Free and above |

> **Note**: Recommended versions are based on production best practices. OpenResty 1.21.4+ enables full regex JIT for optimal performance; Redis 7.0+ offers better memory management and script execution efficiency.

---

## Performance Tuning

### Key Parameters

| Parameter | Default | Recommendation |
|-----------|---------|---------------|
| `redis_connect_timeout_ms` | 30 | Fast fail, keep under 50ms |
| `redis_eval_timeout_ms` | 100 | Give Redis time for Lua computation |
| `redis_keepalive_pool` | Auto-calculated | `maxclients × 0.8 / worker_count`, max 200 |
| `redis_max_connections` | 1024 | Check `redis-cli CONFIG GET maxclients` |
| `malicious_params_min_len` | 8 | Increase to skip more short requests |
| `malicious_params_regex_max_len` | 1024 | Decrease if CPU-bound |
| `global_req_flood_threshold` | 5000 | Per 10s, adjust based on your traffic |
| `bypass_window_limit` | 30 | BYPASS threshold per 60s window (higher than MISS=8 for legitimate use) |
| `miss_window_limit` | 8 | MISS threshold per 60s window (normal first visits) |

### Worker Count & Redis Connection Pool

The connection pool size is auto-calculated per worker:

```lua
pool_per_worker = min(200, max(10, floor(max_redis_connections × 0.8 / worker_count)))
```

For 8 workers with Redis `maxclients=10000`:
`pool = min(200, 10000 × 0.8 / 8) = 200` per worker = 1600 total connections.

---

## Glossary

- **lua_shared_dict**: Cross-worker shared memory dictionary provided by OpenResty for storing global state
- **cosocket**: Non-blocking socket API in OpenResty for high-performance network communication
- **Entropy Score**: A measure of string randomness; high entropy often indicates malicious payloads
- **Distributed Lock**: Mechanism to ensure atomic operations across multiple workers/servers
- **Regex JIT**: Just-in-time compilation of regular expressions by LuaJIT, can speed up matching by 3-10x
- **Circuit Breaker**: Protection mechanism that fails fast and degrades when a dependent service (like Redis) fails
- **Original URI Validation**: Uses `ngx.var.request_uri` (pre-rewrite) instead of `ngx.var.uri` (post-rewrite) for path matching, preventing WordPress URL rewriting from breaking exemption logic

---

## FAQ

### Q: Why do logged-in users still get checked?

A: Full exemption creates an attack surface if admin credentials are compromised. The baseline check retains critical protections (RCE, path traversal, extreme UA, query length) while skipping expensive operations (Redis scoring, SQLi/XSS regex, entropy calculation). The cookie must have WordPress signature format (`user|expiry|token|hmac`) to be accepted.

### Q: How does the WAF distinguish between normal refreshes and malicious bypass?

A: Normal browser refreshes produce cache `MISS` (first visit or expired cache). Malicious bypass produces `BYPASS` (active cache avoidance). The WAF uses separate thresholds for each and tracks frequency per IP. `bypass_window_limit` (default 30) is higher than `miss_window_limit` (default 8) to accommodate legitimate use cases.

### Q: What happens when Redis is down?

A: The circuit breaker activates with stair-step backoff (10s→20s→60s). The WAF continues to provide basic protection via local shared memory:
- Checks local ban cache
- Blocks high-risk requests (quick_score ≥ 35)
- Escalates to stricter thresholds during extended outages (>30s)
- Background timer automatically probes Redis for recovery

### Q: Can this WAF run without Cloudflare?

A: While optimized for Cloudflare, yes. The CF trust scoring will be minimal but all other protection layers remain functional. Set `bypass_block_immediately = false` if you're not behind a CDN, as all direct requests would have "bypass" characteristics.

### Q: How to update malicious parameter rules?

A: Edit the `malicious_rce`, `malicious_sqli`, and `malicious_xss` tables in the `cfg` section and reload Nginx (`nginx -s reload`). No compilation needed.

### Q: How to check WAF runtime status?

A: Use the programmatic API to get status:

```lua
local status = waf.get_status()
ngx.say("Current mode: ", status.mode)
ngx.say("Exact whitelist count: ", #status.whitelist_exact)
ngx.say("Prefix whitelist count: ", #status.whitelist_prefix)
ngx.say("Last whitelist reload: ", status.last_whitelist_reload)
```

---

## Security Design Notes

### Regex Safety

- All regex uses `"joi"` flags: JIT compile, match once, case-insensitive
- Input truncated to `cfg.malicious_params_regex_max_len` (default 1024) to prevent ReDoS
- `pcall` wraps all regex operations; failures fail open (don't block requests)
- Patterns automatically add `\b` word boundaries where appropriate

### Recursive URL Decoding

- Maximum 20 iterations to prevent infinite loops
- Detects multi-encoding bypass attempts (`%252e → %2e → .`)
- Full decode used for path traversal detection; partial decode for param matching

### Resource Protection

- `set_keepalive` failure → explicit `close()` to prevent FD leaks
- `pcall + finally` pattern ensures file handles and Redis connections are always released
- `ngx.timer.at` used in log phase (cosocket not allowed in log phase)
- `ZREMRANGEBYRANK` used instead of `unpack(zrange...)` to prevent stack overflow on large sorted sets

### Distributed Lock Safety

- Lock value includes PID and timestamp for identity verification
- `safe_release_distributed_lock()` only deletes if value matches (prevents cross-worker race conditions)
- Expired lock detection with 2-second clock drift tolerance
- NTP time synchronization recommended for production

### TOCTOU Race Protection

- Shared memory counter get+check+set merged into single `pcall`
- Circuit breaker reset uses atomic verification
- Distributed locks release only on value match

---

## Contributing

Contributions are welcome! Please submit Issues and Pull Requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

If you discover a security vulnerability, please report it privately rather than opening a public Issue.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2024-2026

---

## Disclaimer

This WAF is provided "as is", without warranty of any kind, express or implied. While designed for production WordPress sites behind Cloudflare, you should thoroughly test all configurations in a staging environment before deploying to production. The authors are not responsible for any blocks, data loss, or service interruptions caused by the use of this software.
