# WAF 配置参考指南

所有配置项位于 `openresty-cloudflare-wp-waf.lua` 的 `local cfg = { ... }` 中。修改后执行 `nginx -s reload` 生效。

---

## 目录

- [Redis 连接配置](#redis-连接配置)
- [风控核心阈值](#风控核心阈值)
- [封禁时长配置](#封禁时长配置)
- [已登录用户基线配置](#已登录用户基线配置)
- [窗口与限流配置](#窗口与限流配置)
- [白名单配置](#白名单配置)
- [全局模式自动切换](#全局模式自动切换)
- [参数检测配置](#参数检测配置)
- [轻量级评分阈值](#轻量级评分阈值)
- [CF 回源防护配置](#cf-回源防护配置)
- [恶意规则库](#恶意规则库)
- [路径穿越检测](#路径穿越检测)
- [功能开关](#功能开关)
- [状态端点配置](#状态端点配置)

---

## Redis 连接配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `redis_host` | `"127.0.0.1"` | Redis 服务器地址 |
| `redis_port` | `6379` | Redis 端口 |
| `redis_db` | `0` | Redis 数据库编号 |
| `redis_pass` | `nil` | Redis 密码（无密码设为 `nil`） |
| `redis_connect_timeout_ms` | `30` | TCP 连接超时（毫秒），快速失败避免排队 |
| `redis_eval_timeout_ms` | `100` | eval/eval sha 操作超时（毫秒），给 Redis 充足计算时间 |
| `redis_keepalive_ms` | `10000` | 连接池保持时间（毫秒） |
| `redis_max_connections` | `1024` | Redis 最大连接数，须 ≤ `redis-cli CONFIG GET maxclients` |
| `redis_keepalive_pool` | 动态计算 | 每个 Worker 的连接池大小，自动按 Worker 数量分配 |
| `redis_max_failures` | `5` | 连续失败 N 次触发熔断器 |
| `redis_circuit_breaker_ttl` | `60` | 熔断最大时长（秒），阶梯退避上限 |
| `redis_circuit_breaker_init_ttl` | `10` | 首次熔断时长（秒），短暂波动快速恢复 |
| `redis_probe_interval` | `3` | 熔断期间后台探测间隔（秒） |

### 连接池自动计算

```lua
-- 公式：max_connections × 80% ÷ worker_count
-- 示例：8 workers → 1024 × 0.8 ÷ 8 = 102 per worker
redis_keepalive_pool = calculate_redis_pool_size()
```

> **注意**：`redis_max_connections` 必须 ≤ Redis 实际 maxclients。超过时新的 Redis 连接会失败。

---

## 风控核心阈值

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `risk_ban_threshold` | `100` | 风险分达到此值触发封禁 |
| `rep_ban_threshold` | `20` | 信誉分低于此值触发封禁 |
| `base_burst_10s` | `18` | 10 秒基础突发请求上限 |
| `base_slow_60s` | `12` | 60 秒基础慢速请求上限 |
| `score_ttl` | `1200` | 风险分/信誉分有效期（秒） |
| `risk_decay_ratio` | `0.03` | 风险分自然衰减率（每周期衰减 3%） |

---

## 封禁时长配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `ban_soft` | `900`（15 分钟） | 轻度封禁时长 |
| `ban_mid` | `3600`（1 小时） | 中度封禁时长 |
| `ban_hard` | `86400`（24 小时） | 重度封禁时长 |
| `local_ban_cache_ttl` | `300`（5 分钟） | 本地共享内存封禁缓存 TTL |

---

## 已登录用户基线配置

已登录用户不再完全豁免，而是执行精简版安全检查：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `logged_user_enable` | `true` | 是否启用已登录用户分层保护 |
| `logged_user_post_burst_limit` | `60` | 已登录用户 POST 频率上限（/60s） |
| `logged_user_query_hard_limit` | `4000` | 已登录用户 query 长度硬限制 |
| `logged_user_rce_only` | `true` | 仅检查 RCE 恶意参数，跳过 SQLi/XSS |
| `logged_user_wp_asset_burst_10s` | `40` | WP 管理资产 10s 窗口最大请求数 |
| `logged_user_wp_asset_slow_60s` | `180` | WP 管理资产 60s 窗口最大请求数 |

> `logged_user_rce_only = true` 时，登录用户的参数检测只扫描 RCE 模式，不检查 SQLi 和 XSS（登录用户的可信度更高，同时 RCE 是最危险的攻击类型）。

---

## 窗口与限流配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `seen_ttl` | `300` | URI 访问记录窗口（秒） |
| `burst_ttl` | `10` | 突发速率窗口（秒） |
| `slow_ttl` | `60` | 慢速速率窗口（秒） |
| `miss_window_ttl` | `60` | CDN MISS 事件统计窗口（秒） |
| `miss_window_limit` | `8` | 60 秒内 MISS 超过此次数触发惩罚 |
| `bypass_window_ttl` | `60` | CDN BYPASS 事件统计窗口（秒） |
| `bypass_window_limit` | `30` | 60 秒内 BYPASS 超过此次数触发惩罚 |

> **为什么 MISS 阈值比 BYPASS 低**：MISS 是正常首次访问的标志，过高阈值会误伤；BYPASS 是主动绕过缓存，嫌疑更大。

---

## 白名单配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `whitelist_refresh_interval` | `300` | 白名单文件自动刷新间隔（秒） |
| `local_allow_file` | `"/www/server/nginx/lua/waf_whitelist.txt"` | IP 白名单文件路径 |

白名单文件格式（每行一个 IP 或 CIDR 网段）：

```
127.0.0.1
10.0.0.0/8
192.168.1.0/24
172.16.0.0/12
```

---

## 全局模式自动切换

WAF 有 4 个全局模式：**正常(0) → 防御(1) → 高防(2) → 熔断(3)**。自动切换基于全局计数器（MISS/BYPASS/熵值）。

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `global_counter_ttl` | `10` | 全局计数器窗口（秒） |
| `global_attack_miss_threshold` | `5` | 触发攻击模式的 MISS 阈值 |
| `global_attack_bypass_threshold` | `3` | 触发攻击模式的 BYPASS 阈值 |
| `global_attack_entropy_threshold` | `5` | 触发攻击模式的熵值阈值 |
| `global_origin_miss_threshold` | `10` | 触发回源保护的 MISS 阈值 |
| `global_origin_bypass_threshold` | `6` | 触发回源保护的 BYPASS 阈值 |
| `global_origin_entropy_threshold` | `8` | 触发回源保护的熵值阈值 |
| `attack_mode_ttl` | `90` | 攻击模式持续时间（秒） |
| `origin_protect_ttl` | `60` | 回源保护模式持续时间（秒） |

> **滞后区间**：模式 3 退出阈值 = 进入阈值 × 0.7，避免边界震荡。

---

## 参数检测配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `query_entropy_args_soft_len` | `48` | 参数总长度达到此值时开始软判断 |
| `query_entropy_args_hard_len` | `96` | 参数总长度达到此值时硬拦截 |
| `query_entropy_trigger_score` | `2` | 触发 Redis 深度检测的熵值评分 |
| `query_entropy_value_soft_len` | `12` | 单个值长度达到此值时软判断 |
| `query_entropy_token_soft` | `4` | 参数 token 数量达到此值时软判断 |
| `query_entropy_ratio_threshold` | `0.72` | 熵值阈值（0-1），超过视为可疑 |
| `html_query_max_len` | `128` | 正常模式下 HTML 请求的查询长度限制 |
| `attack_html_query_max_len` | `64` | 攻击模式下 HTML 请求的查询长度限制 |
| `origin_html_query_max_len` | `32` | 回源保护模式下 HTML 请求的查询长度限制 |
| `global_query_hard_limit` | `1024` | 全局查询长度硬限制（所有模式共享） |

---

## 轻量级评分阈值

访问阶段 2 使用快速评分来决定是否进入 Redis 深度检测：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `normal_light_score_threshold` | `8` | 正常模式下触发 Redis 的分数阈值 |
| `light_score_bypass` | `4` | 检测到缓存绕过信号加 N 分 |
| `light_score_entropy` | `4` | 高熵值参数加 N 分 |
| `light_score_sensitive` | `4` | 敏感路径（如 /wp-admin）加 N 分 |
| `light_score_post_no_referer` | `3` | POST 无 Referer 加 N 分 |
| `light_score_html_cookie_referer` | `-2` | HTML 请求有 Cookie + Referer 减 N 分 |
| `light_score_homepage` | `-1` | 首页请求减 N 分 |
| `miss_bump_score` | `15` | MISS 事件在反馈阶段加 N 分 |
| `bypass_bump_score` | `30` | BYPASS 事件在反馈阶段加 N 分 |

> `light_score_html_cookie_referer = -2` 和 `light_score_homepage = -1` 是负分，降低正常用户的误判率。

---

## CF 回源防护配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `bypass_limit_per_ip_60s` | `15` | 单 IP 60 秒内最大 BYPASS 次数 |
| `global_req_flood_threshold` | `5000` | 10 秒内全局总请求洪水阈值 |
| `bypass_block_immediately` | `true` | 是否立即拦截缓存绕过信号（含首次访问豁免） |
| `cluster_ttl` | `300` | 集群攻击检测时间窗口（秒） |
| `cluster_threshold` | `6` | 集群攻击触发阈值（同 URI/IP 访问数） |
| `cluster_penalty` | `20` | 集群攻击惩罚分数 |
| `enable_waf_cache_headers` | `true` | 是否由 WAF 添加 Cache-Control 响应头 |

`allowed_http_methods` 表定义允许的 HTTP 方法：

```lua
allowed_http_methods = {
    GET = true, HEAD = true, POST = true,
    OPTIONS = true, PUT = true, DELETE = true, PATCH = true,
}
```

> 不在白名单中的方法（如 TRACE、CONNECT）直接返回 405。

---

## 恶意规则库

### 可疑 UA 黑名单（`malicious_uas`）

大小写不敏感，前缀匹配。用于评分机制，不是硬拦截。

默认包含：curl、wget、python-requests、scrapy、okhttp、phantomjs、selenium、nmap、sqlmap、nikto、burp、gobuster、ffuf 等常见扫描器/工具。

### 恶意参数关键字

按攻击类型分为三组，支持上下文感知动态选择检测组：

**组 1 — RCE/代码注入（`malicious_rce`）**：对所有请求生效。
```
shell, cmd, eval(, system(, exec(, phpinfo, passthru,
popen, proc_open, assert(, file_get_contents, include(,
require(, include_once, require_once
```

**组 2 — SQL 注入（`malicious_sqli`）**：仅在参数含 SQL 特征时检测（`'`、`;`、`@` 等），跳过约 80% 正常流量。
```
xp_cmdshell, sp_configure, exec master, union+select,
sleep(, benchmark(, @@, char(, concat(, cast(, convert(
```

**组 3 — XSS（`malicious_xss`）**：仅对 HTML 类端点检测，API/静态资源跳过。
```
alert(, script>, onload=, onerror=, onclick=,
javascript:, vbscript:, data:text, base64,
```

### 正则安全配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `malicious_params_regex_max_len` | `1024` | 检测输入长度硬上限，防 ReDoS 回溯 |
| `malicious_params_min_len` | `8` | 最短参数门控，短于此值直接跳过 |

---

## 路径穿越检测

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `path_traversal_signals` | `{ "../", "./", "//", "\\", "%00", "%0a", "%0d", "%09" }` | 路径穿越检测关键字 |

> 注意：分号 `;` 已从列表中移除，避免误伤正常的 REST API 调用和分号参数分隔。

---

## 功能开关

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `block_xmlrpc` | `true` | 拦截 XMLRPC 请求 |
| `block_empty_cookie` | `true` | 拦截空 Cookie 的 HTML 请求 |
| `block_empty_referer` | `true` | 拦截空 Referer 的 POST 请求 |
| `block_malicious_params` | `true` | 启用恶意参数关键字检测 |
| `block_path_traversal` | `true` | 启用路径穿越攻击检测 |
| `enable_local_rate_limit` | `true` | 启用本地频率限制 |
| `log_level` | `"info"` | 日志级别：`debug` / `info` / `warn` / `error` |
| `enable_debug_log` | `false` | 开启详细调试日志（高流量环境慎用） |
| `force_block_log_error` | `true` | 强制所有拦截日志以 ERROR 级别记录 |

---

## 状态端点配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `status_endpoint_enabled` | `false` | 是否启用运行状态 HTTP 端点 |
| `status_endpoint_path` | `"/waf-status"` | 端点访问路径 |
| `status_endpoint_allowed_ips` | `{"127.0.0.1"}` | 允许访问的 IP 列表 |
| `status_metrics_ttl_days` | `7` | 状态指标的独立 Redis 存储时长（天），设为 `0` 永久保留 |

启用后访问 `GET /waf-status` 即可获取纯文本格式的运行状态报告（含独立存储的请求/拦截统计）。非白名单 IP 返回 404。

> `status_metrics_ttl_days` 控制的指标存储在 Redis 独立键空间（`wf:status:*`），不受 `global_counter_ttl` 影响。仅在 `status_endpoint_enabled = true` 时启用。

---

## 调优指南

### 降低误拦率

```lua
-- 提高阈值，给正常用户更多空间
risk_ban_threshold = 150      -- 默认 100
base_burst_10s = 30           -- 默认 18
base_slow_60s = 20            -- 默认 12

-- 降低轻量评分激进程度
light_score_entropy = 2       -- 默认 4
normal_light_score_threshold = 10  -- 默认 8

-- 关闭缓存绕过立即拦截
bypass_block_immediately = false
```

### 提高安全级别

```lua
-- 降低阈值，更积极拦截
risk_ban_threshold = 70       -- 默认 100
rep_ban_threshold = 30        -- 默认 20

-- 更长的封禁时间
ban_soft = 1800               -- 30 分钟
ban_mid = 7200                -- 2 小时
ban_hard = 172800             -- 48 小时

-- 更严格的全局模式切换
global_origin_miss_threshold = 6   -- 默认 10（更容易触发回源保护）
```

### 非 Cloudflare 环境

```lua
bypass_block_immediately = false   -- 关闭立即拦截（所有请求都像绕过）
light_score_bypass = 0             -- CF 信任分不可用时清零
cf_score = 0                       -- 没有 CF 头时手动清零
```
