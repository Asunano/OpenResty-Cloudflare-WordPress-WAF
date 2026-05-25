
-- WP + Cloudflare + Redis 统一风控


package.path =
    "/www/server/nginx/lualib/?.lua;/www/server/nginx/lualib/?/init.lua;" ..
    package.path

local redis = require "resty.redis"
local re = require "ngx.re"
local _M = {}
local MODULE_NAME = ...
local bit = nil
pcall(function() bit = require "bit" end)
if not bit then
    ngx.log(ngx.ERR, "[WAF] bit库未安装，使用纯Lua位运算降级")
end

-- 纯 Lua 位与运算：bit 库不可用时降级替代，支持任意前缀长度的 CIDR 匹配
local function lua_band(a, b)
    local result = 0
    local bitval = 1
    for _ = 1, 32 do
        if a % 2 == 1 and b % 2 == 1 then
            result = result + bitval
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bitval = bitval * 2
    end
    return result
end
local function get_worker_pid()
    if ngx.worker and type(ngx.worker.pid) == "function" then
        return ngx.worker.pid()
    end
    -- 降级方案：使用 ngx.var.pid 或随机数
    local ok, pid = pcall(function()
        return ngx.var and ngx.var.pid
    end)
    return (ok and tonumber(pid)) or math.random(100000, 999999)
end
-- 结合时间戳、Worker PID 和随机数生成唯一种子
--  注意：math.randomseed 在 init_worker 中调用，避免模块级副作用干扰其他库
local math_seeded = false

local function get_worker_count()
    if ngx.worker and type(ngx.worker.count) == "function" then
        local ok, count = pcall(ngx.worker.count)
        if ok and count and count > 0 then
            return count
        end
    end
    -- 降级方案：默认 1 个 worker
    return 1
end
local unpack = unpack or table.unpack
local log
local redis_connect
local redis_close
local has_malicious_params_safe
local bump_counter   -- 前向声明：logged_in_user_baseline_check 中需要速率限制
-- EVALSHA 脚本缓存：init_worker 预加载 SHA，避免每次请求发送完整脚本(~5.5KB)
local sha_cache = {}
local function calculate_redis_pool_size()
    local worker_count = get_worker_count()
    if not worker_count or worker_count <= 0 then
        worker_count = 1
    end
    
    -- 🔧 cfg.redis_max_connections 与此处保持同步（当前 1024）
    --    实际值应匹配: redis-cli CONFIG GET maxclients
    local max_redis_connections = 1024
    local safe_connections_per_worker = math.floor(max_redis_connections * 0.8 / worker_count)
    
    -- 设置最小和最大限制
    -- 最小值：10（保证基本性能）
    -- 最大值：200（避免单个 worker 占用过多连接）
    safe_connections_per_worker = math.max(10, math.min(200, safe_connections_per_worker))
    
    ngx.log(ngx.INFO, string.format(
        "[WAF] 自动计算 Redis 连接池大小: worker_count=%d, max_redis_connections=%d, pool_size=%d",
        worker_count, max_redis_connections, safe_connections_per_worker
    ))
    
    return safe_connections_per_worker
end

-- =========================================================
-- 🔧 配置区（所有可修改内容都在这里，无需动下面代码）
-- =========================================================
local cfg = {
    -- Redis配置
    redis_host = "127.0.0.1",
    redis_port = 6379,
    redis_db = 0,
    redis_pass = nil,
    redis_connect_timeout_ms = 30,      -- 🔧 TCP连接超时（快速失败，避免排队）
    redis_eval_timeout_ms = 100,        -- 🔧 Redis eval 操作超时（给Redis计算时间）
    redis_keepalive_ms = 10000,         -- 连接保持时间（毫秒）
    redis_max_connections = 1024,       -- 须 <= Redis maxclients 配置（redis-cli CONFIG GET maxclients）
    -- 总最大连接数 = worker 数量 × redis_keepalive_pool
    -- 示例：8 workers × 100 = 800 个连接
    -- 建议：不超过 Redis 最大连接数（默认 10000）的 80%
    -- 计算：10000 × 0.8 ÷ 8 workers = 1000 per worker
    redis_keepalive_pool = calculate_redis_pool_size(),  --  动态计算连接池大小
    redis_max_failures = 5,             -- 连续失败次数触发熔断
    redis_circuit_breaker_ttl = 60,     -- 熔断最大时长（秒），阶梯退避上限
    redis_circuit_breaker_init_ttl = 10,-- 🔧 首次熔断时长（秒），短暂抖动快速恢复
    redis_probe_interval = 3,           -- 熔断期间后台探测间隔（秒）

    -- 风控核心阈值
    risk_ban_threshold = 100,
    rep_ban_threshold  = 20,
    base_burst_10s = 18,
    base_slow_60s   = 12,
    score_ttl = 1200,
    risk_decay_ratio = 0.03,

    -- 封禁时长配置（秒）
    ban_soft = 900,    -- 15分钟
    ban_mid  = 3600,   -- 1小时
    ban_hard = 86400,  -- 24小时
    local_ban_cache_ttl = 300,  -- 本地封禁缓存5分钟

    --  已登录用户基线配置（非完全豁免，保留基础安全检查）
    logged_user_enable = true,           -- 是否启用已登录用户分层保护
    logged_user_post_burst_limit = 60,   -- 已登录用户 POST 频率上限（/60s）
    logged_user_query_hard_limit = 4000, -- 已登录用户 query 长度硬限制（比 2000 更宽松）
    logged_user_rce_only = true,         -- 仅检查 RCE 类恶意参数（跳过 SQLi/XSS）
    --  WP 管理后台资产速率限制（防豁免变攻击面）
    logged_user_wp_asset_burst_10s = 40, -- WP资产 10s 窗口内最大请求数（单IP）
    logged_user_wp_asset_slow_60s = 180, -- WP资产 60s 窗口内最大请求数（单IP）

    -- 窗口配置
    seen_ttl = 300,
    burst_ttl = 10,
    slow_ttl = 60,
    miss_window_ttl = 60,
    miss_window_limit = 8,            -- MISS阈值：60秒内超过8次MISS才惩罚（正常首次访问）
    bypass_window_ttl = 60,
    bypass_window_limit = 30,         -- BYPASS阈值：只有主动绕过缓存才被CF标记，正常用户刷新/首次访问是miss

    -- 白名单配置
    whitelist_refresh_interval = 300,  -- 白名单自动刷新间隔(秒)
    local_allow_file = "/www/server/nginx/lua/waf_whitelist.txt",  -- IP白名单文件

    -- 全局模式自动切换配置
    global_counter_ttl = 10,
    global_attack_miss_threshold = 5,
    global_attack_bypass_threshold = 3,
    global_attack_entropy_threshold = 5,
    global_origin_miss_threshold = 10,
    global_origin_bypass_threshold = 6,
    global_origin_entropy_threshold = 8,
    attack_mode_ttl = 90,
    origin_protect_ttl = 60,

    -- 参数检测配置
    query_entropy_args_soft_len = 48,
    query_entropy_args_hard_len = 96,
    query_entropy_trigger_score = 2,
    query_entropy_value_soft_len = 12,
    query_entropy_token_soft = 4,
    query_entropy_ratio_threshold = 0.72,
    html_query_max_len = 128,
    attack_html_query_max_len = 64,
    origin_html_query_max_len = 32,
    global_query_hard_limit = 1024,

    -- 轻量级评分阈值
    normal_light_score_threshold = 8,
    light_score_bypass = 4,           -- 缓存绕过信号加分数
    light_score_entropy = 4,           -- 高熵值加分数
    light_score_sensitive = 4,         -- 敏感路径加分数
    light_score_post_no_referer = 3,  -- POST无Referer加分数
    light_score_html_cookie_referer = -2,  -- HTML有Cookie有Referer减分数
    light_score_homepage = -1,         -- 首页减分数
    miss_bump_score = 15,      -- Miss 事件增加的分数
    bypass_bump_score = 30,    -- Bypass 事件增加的分数

    -- CF回源防护配置
    bypass_limit_per_ip_60s = 15,
    global_req_flood_threshold = 5000,  -- 10秒内全局总请求洪水阈值
    bypass_block_immediately = true,
    cluster_ttl = 300,          -- 集群检测时间窗口（秒）
    cluster_threshold = 6,      -- 集群触发阈值
    cluster_penalty = 20,       -- 集群惩罚分数
    allowed_http_methods = {
        GET = true,
        HEAD = true,
        POST = true,
        OPTIONS = true,
        PUT = true,      -- WordPress REST API 需要
        DELETE = true,   -- WordPress REST API 需要
        PATCH = true,    -- WordPress REST API 需要
    },
    enable_waf_cache_headers = true,  -- 是否由 WAF 添加 Cache-Control 头

    -- ==============================================
    --  恶意规则库（一键修改，无需动下面代码）
    -- ==============================================
    -- 可疑UA黑名单（大小写不敏感，支持前缀匹配）
    -- 用于评分机制，不是硬拦截
    malicious_uas = {
        "curl", "wget", "python-requests",
        -- "go-http-client",
        "httpclient", "libwww-perl", "scrapy", "aiohttp",
        "okhttp", "java/",
        -- "headlesschrome",
        "phantomjs",
        "selenium", "puppeteer", "playwright", "httpx",
        "masscan", "nmap", "sqlmap", "nikto", "dirb",
        "gobuster", "ffuf", "wfuzz", "xray", "burp",
        "postmanruntime", "insomnia", "restclient",
        "apachebench", "ab", "siege", "wrk", "hey",
    },

    -- 恶意参数关键字（按攻击类型分组，支持上下文感知动态选择检测组）
    -- 组1：命令执行/代码注入（通用威胁，对所有请求生效）
    malicious_rce = {
        "shell", "cmd", "eval(", "system(", "exec(",
        "phpinfo", "passthru", "popen", "proc_open", "assert(",
        "file_get_contents", "include(", "require(", "include_once",
        "require_once",
    },
    -- 组2：SQL 注入（仅在参数含 SQL 特征字符时检测）
    malicious_sqli = {
        "xp_cmdshell", "sp_configure", "exec master",
        "union+select", "union%20select", "and+1=1", "or+1=1", "sleep(",
        "benchmark(", "md5(", "sha1(", "version()",
        "'", "--", ";--", "/*", "*/", "@@",
        "char(", "concat(", "cast(", "convert(",
    },
    -- 组3：XSS 跨站脚本（仅对 HTML 类端点检测，API/静态资源跳过）
    malicious_xss = {
        "alert(", "script>", "onload=", "onerror=", "onclick=",
        "javascript:", "vbscript:", "data:text", "base64,",
        "hack",  -- 通用恶意关键字
    },

    --  正则安全：恶意参数检测输入长度硬上限（防止极端长字符串导致回溯）
    -- 超过此长度的输入截断处理，仅匹配前 N 字符
    -- 值 1024：正常 query 极少超此值，且恶意特征通常在头部出现
    malicious_params_regex_max_len = 1024,
    -- 🔧 最短参数门控：args 短于此值直接跳过（如 p=1 / s=ab 无恶意特征）
    -- 最短有意义恶意模式 "sleep(" / "eval(" / "cmd" 接近此长度
    malicious_params_min_len = 8,

    -- 路径穿越/URL污染关键字（仅保留原始形式，检测时会先URL解码）
    path_traversal_signals = {
        "../", "./", "//", "\\",
        "%00", "%0a", "%0d", "%09",
    },

    -- ==============================================
    --  功能开关（true=开启 false=关闭）
    -- ==============================================
    block_xmlrpc = true,          -- 拦截XMLRPC请求
    block_empty_cookie = true,    -- 拦截空Cookie的HTML请求
    block_empty_referer = true,   -- 拦截空Referer的POST请求
    block_malicious_params = true,-- 拦截恶意参数关键字
    block_path_traversal = true,  -- 拦截路径穿越攻击
    enable_local_rate_limit = true, -- 启用本地频率限制
    log_level = "info",           -- 日志级别: debug/info/warn/error
    enable_debug_log = false,     -- 开启详细调试日志
    force_block_log_error = true, -- 强制所有拦截日志为error级别

    -- 运行状态端点（仅白名单 IP 可访问）
    status_endpoint_enabled = false,         -- 是否启用状态查看端点
    status_endpoint_path = "/waf-status",   -- 访问路径
    status_endpoint_allowed_ips = {          -- 允许访问的 IP 列表
        "127.0.0.1",
    },
    -- 状态指标独立 Redis 存储（不受 global_counter_ttl 影响）
    status_metrics_ttl_days = 7,             -- 指标保存时长（天），设为 0 则永久保留
}

-- =========================================================
-- 全局变量（无需修改）
-- =========================================================
local SH_BAN = ngx.shared.wf_ban_cache
local SH_META = ngx.shared.wf_meta_cache

-- =========================================================
--  前向声明（解决作用域问题）
-- =========================================================
-- log / redis_connect / redis_close 已在文件顶部统一前向声明

-- =========================================================
--  统一拦截函数（确保所有拦截点一致）
-- =========================================================
local function block_request(reason, ip, uri, context, status_code)
    --[[
        统一拦截函数，确保所有拦截点行为一致
        
        参数:
            reason: 拦截原因（日志事件名）
            ip: 客户端IP
            uri: 请求URI
            context: 额外上下文信息（可选）
            status_code: HTTP返回码（默认403）
        
        返回:
            不返回，直接exit
    ]]
    local code = status_code or 403
    log("warn", reason, ip, uri, context or "")
    if ngx.ctx.redis_conn then
        redis_close(ngx.ctx.redis_conn)
        ngx.ctx.redis_conn = nil
    end
    -- 后果：CDN 会缓存 403 页面，导致正常用户也看到 403
    ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"
    -- Cloudflare 额外防护头：CDN-Cache-Control 在部分代理中比 Cache-Control 优先级更高
    ngx.header["CDN-Cache-Control"] = "no-cache, no-store"
    ngx.header["Surrogate-Control"] = "no-store"
    ngx.header["X-WAF-Bypass-Stage"] = nil  -- 清除 bypass 阶段标记
    ngx.header["X-WAF-Bypass-Count"] = nil  -- 清除 bypass 计数
    
    ngx.ctx.wf_skip = true
    ngx.ctx.wf_exit_code = code  -- 保存退出码，供后续阶段使用
    return ngx.exit(code)
end

-- 便捷函数：频率限制
local function rate_limit_block(ip, uri, context)
    return block_request("RATE_LIMITED", ip, uri, context, 429)
end

-- =========================================================
-- 全局模式配置
-- =========================================================
local global_mode = {
    mode = 0,  -- 0正常 1防御 2高防 3熔断
    auto_mode = true,
    entropy_threshold = 0.72,
    circuit_breaker = {
        enabled = true,
        ban_rate_threshold = 0.20,
        window = 60
    }
}

-- =========================================================
-- 工具函数（最优先定义，避免作用域问题）
-- =========================================================
local function now()
    return ngx.now()
end

local function starts_with(s, prefix)
    return s and prefix and s:sub(1, #prefix) == prefix
end

local function tolower(v)
    if type(v) ~= "string" then
        return ""
    end
    return v:lower()
end
-- 功能：将可能为 Table 的值安全转换为字符串
-- 场景：当用户发送重复参数时（如 ?id=1&id=2），ngx.req.get_uri_args() 返回 Table
-- 如果直接传入 ngx.re.find() 会导致：bad argument #1 to 'find' (string expected, got table)
local function flatten_value(v)
    if not v then return "" end
    
    if type(v) == "table" then
        -- 将多值参数用空格拼接，既保证了正则能统检，又避免了类型错误
        return table.concat(v, " ")
    end
    
    return tostring(v)
end
-- 功能：支持读取大请求的文件缓存，封堵绕过漏洞
-- 场景：攻击者在恶意载荷前填充垃圾数据，使 body 超过 client_body_buffer_size
-- 如果只使用 get_body_data()，会返回 nil，导致检测被绕过
local function get_secure_body_data()
    local content_type = ngx.var.content_type or ""
    local ct_lower = content_type:lower()
    if not ct_lower:find("application/x-www-form-urlencoded", 1, true)
       and not ct_lower:find("multipart/form-data", 1, true)
       and not ct_lower:find("application/json", 1, true)
       and not ct_lower:find("text/xml", 1, true) then
        return ""
    end

    ngx.req.read_body()
    local body_data = ngx.req.get_body_data()
    
    if not body_data then
        local body_file = ngx.req.get_body_file()
        if body_file then
            --  路径安全校验：防止路径穿越和符号链接攻击
            if body_file:find("..", 1, true) then
                ngx.log(ngx.ERR, "[WAF] 请求体文件路径包含 ..", body_file)
                return ""
            end
            -- 验证文件路径在合法的临时目录下
            local valid_prefix = body_file:match("^(/tmp/)|^(/var/tmp/)|^(/dev/shm/)|^(/var/lib/nginx/)")
            if not valid_prefix then
                ngx.log(ngx.WARN, "[WAF] 请求体文件不在标准临时目录: ", body_file)
                return ""
            end
            -- 证明数据被缓存到了磁盘文件，打开并读取前 512KB（兼顾性能与安全）
            local f, err = io.open(body_file, "r")
            if f then
                local ok, read_err = pcall(function()
                    body_data = f:read(524288)  -- 512 KB
                end)
                -- 无论读取成功还是失败，都必须关闭文件句柄
                local _, close_err = pcall(f.close, f)
                if not ok then
                    ngx.log(ngx.WARN, string.format(
                        "[WAF] 读取请求体文件数据失败: path=%s err=%s",
                        body_file or "nil", read_err or "unknown error"))
                end
                if close_err then
                    ngx.log(ngx.WARN, string.format(
                        "[WAF] 关闭请求体文件失败: path=%s err=%s",
                        body_file or "nil", close_err or "unknown error"))
                end
            else
                ngx.log(ngx.WARN, string.format(
                    "[WAF] 读取请求体文件失败: path=%s err=%s",
                    body_file or "nil", err or "unknown error"))
            end
        end
    end
    
    return body_data or ""
end

-- 自定义正则转义函数（OpenResty无ngx.re.escape）
local function regex_escape(s)
    return s:gsub("[%.%^%$%*%+%?%(%)%[%]%{%}|\\/-]", "\\%1")
end

-- 预编译恶意参数正则（提升性能）
local re_ok, re_module = pcall(require, "ngx.re")

--  优化：按攻击类型分组编译正则，减少单体正则的 alternation 数量
-- 每组独立编译，支持上下文感知的动态启用/跳过
--  将恶意模式列表编译为 alternation 正则
--  ReDoS 防护：_has_sqli_literals() 预筛跳过 ~80% 请求 + 1024 字符截断 + joi JIT 标志
local function _build_group_re(pattern_list)
    if not pattern_list or #pattern_list == 0 then
        return nil
    end
    local patterns = {}
    for _, p in ipairs(pattern_list) do
        if p and type(p) == "string" and p ~= "" then
            local escaped = regex_escape(p)
            if escaped and type(escaped) == "string" then
                local start_boundary = p:match("^[^%w_]") and "" or "\\b"
                local end_boundary = p:match("[^%w_]$") and "" or "\\b"
                table.insert(patterns, start_boundary .. escaped .. end_boundary)
            end
        end
    end
    if #patterns == 0 then
        return nil
    end
    return "(" .. table.concat(patterns, "|") .. ")"
end

local malicious_rce_re, malicious_sqli_re, malicious_xss_re
local malicious_groups_initialized = false

local function init_malicious_params_re()
    if not malicious_groups_initialized then
        malicious_rce_re  = _build_group_re(cfg.malicious_rce)
        malicious_sqli_re = _build_group_re(cfg.malicious_sqli)
        malicious_xss_re  = _build_group_re(cfg.malicious_xss)
        malicious_groups_initialized = true
    end
    return malicious_rce_re, malicious_sqli_re, malicious_xss_re
end
-- 采用"默认字符串 + 条件晋升编译对象"的平滑降级策略
--       后续调用 ngx.re.find(subject, nil, "jo") 会导致致命错误：bad argument #2 to 'find' (string expected, got nil)
local WP_LOGGED_IN_RE = "wordpress_logged_in_"  -- 默认字符串模式
local WP_SEC_RE = "wordpress_sec_"
local COMMENT_AUTHOR_RE = "comment_author_"
local WOOCOMMERCE_CART_RE = "woocommerce_items_in_cart"

if re_ok and re_module and re_module.compile then
    -- 高版本OpenResty：使用预编译正则，性能提升30%+
    pcall(function()
        WP_LOGGED_IN_RE = re_module.compile("wordpress_logged_in_", "joi")
        WP_SEC_RE = re_module.compile("wordpress_sec_", "joi")
        COMMENT_AUTHOR_RE = re_module.compile("comment_author_", "joi")
        WOOCOMMERCE_CART_RE = re_module.compile("woocommerce_items_in_cart", "joi")
    end)
end

-- =========================================================
-- 全局模式自动管理（提前定义，解决作用域问题）
-- =========================================================
local function get_mode()
    if not SH_META then
        return 0
    end
    local ok, value = pcall(function()
        return SH_META:get("wf:mode:level")
    end)
    
    if not ok then
        ngx.log(ngx.ERR, string.format(
            "[WAF] [ERROR] [MODE_GET] 读取模式失败: %s，返回默认值 0", 
            tostring(value)))
        return 0
    end
    
    return tonumber(value) or 0
end

local function set_mode(level, ttl, reason)
    if not SH_META then
        ngx.log(ngx.ERR, "[WAF] [ERROR] [MODE_SWITCH] SH_META 未初始化，无法切换模式")
        return false
    end
    level = tonumber(level) or 0
    ttl = tonumber(ttl) or 90
    if ttl <= 0 then
        ttl = 90  -- 兜底 90 秒
    end
    
    --  TOCTOU 竞态保护：get+check+set 原子化到同一 pcall，竞态窗口缩小到微秒级（SH_META:get() → SH_META:set()）
    --  关键：SH_META:set() 失败时返回 (false, "no memory") 而非抛异常，需在 pcall 内用 error() 转换为异常
    local old_level = 0
    local ok, err = pcall(function()
        old_level = tonumber(SH_META:get("wf:mode:level")) or 0
        if old_level == level then
            return true  -- 已处于目标模式，跳过写入
        end
        local set_ok, set_err = SH_META:set("wf:mode:level", level, ttl)
        if not set_ok then
            error("set failed: " .. tostring(set_err))
        end
        return true
    end)
    
    if not ok then
        ngx.log(ngx.ERR, string.format(
            "[WAF] [ERROR] [MODE_SWITCH] 设置模式失败: %s", 
            tostring(err)))
        return false
    end
    
    if ok then
        ngx.log(ngx.INFO, string.format(
            "[WAF] [INFO] [GLOBAL_MODE_CHANGE] 模式变更：%d → %d，原因：%s，持续 %d 秒",
            old_level, level, reason or "unknown", ttl))
    end
    if reason then
        pcall(function()
            SH_META:set("wf:mode:last_reason", reason, ttl)
        end)
    end
    
    return ok
end

local function clear_mode()
    if not SH_META then
        ngx.log(ngx.ERR, "[WAF] [ERROR] [MODE_SWITCH] SH_META 未初始化，无法清除模式")
        return false
    end
    
    --  TOCTOU 竞态保护：get+check+set 合并到同一 pcall
    local old_level = 0
    local ok, err = pcall(function()
        old_level = tonumber(SH_META:get("wf:mode:level")) or 0
        if old_level == 0 then
            return true  -- 已处于正常模式
        end
        return SH_META:set("wf:mode:level", 0, 86400)
    end)
    
    if not ok then
        ngx.log(ngx.ERR, string.format(
            "[WAF] [ERROR] [MODE_CLEAR] 清除模式失败: %s", 
            tostring(err)))
        return false
    end
    
    if old_level > 0 then
        ngx.log(ngx.INFO, string.format(
            "[WAF] [INFO] [GLOBAL_MODE_CLEAR] 从 %d 恢复到正常模式",
            old_level))
    end
    
    return ok
end

-- =========================================================
-- 白名单文件加载与缓存
-- =========================================================
-- =========================================================
-- IP白名单管理（支持CIDR网段）
-- 白名单在worker启动时加载到内存，正常模式下定时刷新
-- =========================================================
local whitelist_ips = {       -- 单个IP列表（哈希表，O(1)查找）
    ["127.0.0.1"] = true,
}
local whitelist_cidrs = {}    -- CIDR网段列表（数组，遍历匹配）
local whitelist_last_refresh = 0  -- 最后刷新时间

-- 将IP转换为数字（用于CIDR匹配）
-- IP地址转数字（带校验）
local function ip_to_number(ip)
    if not ip or type(ip) ~= "string" then
        return nil
    end
    
    -- 去除首尾空格
    ip = ip:gsub("^%s+", ""):gsub("%s+$", "")
    
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or d < 0 or d > 255 then
        return nil
    end
    
    return a * 256^3 + b * 256^2 + c * 256 + d
end

-- CIDR 格式校验函数
local function validate_cidr(cidr)
    if not cidr or type(cidr) ~= "string" then
        return false, "无效输入"
    end
    
    -- 去除首尾空格
    cidr = cidr:gsub("^%s+", ""):gsub("%s+$", "")
    
    local network, prefix_len = cidr:match("^([^/]+)/(%d+)$")
    if not network then
        return false, "格式错误：缺少 / 分隔符"
    end
    
    -- 验证网络地址
    local a, b, c, d = network:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return false, "网络地址格式错误"
    end
    
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or d < 0 or d > 255 then
        return false, "网络地址超出范围"
    end
    
    -- 验证前缀长度
    prefix_len = tonumber(prefix_len)
    if not prefix_len or prefix_len < 0 or prefix_len > 32 then
        return false, "前缀长度无效（应为 0-32）"
    end
    
    return true, nil
end

-- 检查IP是否在CIDR网段内
local function ip_in_cidr(ip, cidr)
    if not ip or not cidr then return false end
    local network, prefix_len = cidr:match("([^/]+)/(%d+)")
    if not network or not prefix_len then return false end
    
    local ip_num = ip_to_number(ip)
    local network_num = ip_to_number(network)
    if not ip_num or not network_num then return false end
    
    prefix_len = tonumber(prefix_len)
    local mask = (2^32 - 1) - ((2^(32 - prefix_len)) - 1)
    
    if bit then
        return bit.band(ip_num, mask) == bit.band(network_num, mask)
    else
        -- 纯 Lua 位运算降级：使用 lua_band 替代 bit.band，支持任意前缀长度
        return lua_band(ip_num, mask) == lua_band(network_num, mask)
    end
end

--  安全释放分布式锁：值匹配才删除，防止检查-删除竞态（锁过期后被其他worker抢占时不会误删）
local function safe_release_distributed_lock(lock_key, expected_lock_val)
    if not SH_META or not lock_key then
        return
    end

    -- 获取当前锁值
    local current_lock_val = SH_META:get(lock_key)

    -- 只有锁值完全匹配时才删除（防止误删其他 worker 刚获取的锁）
    if current_lock_val == expected_lock_val then
        SH_META:delete(lock_key)
        ngx.log(ngx.DEBUG, string.format(
            "[WAF] 安全释放锁 %s (val=%s)", lock_key, expected_lock_val))
    else
        ngx.log(ngx.WARN, string.format(
            "[WAF] 跳过释放锁 %s：当前值=%s，预期值=%s（可能被其他 worker 持有）",
            lock_key, tostring(current_lock_val), expected_lock_val))
    end
end
-- ⚠️ 前置条件：生产环境所有服务器应配置 NTP 时间同步
-- 本实现使用 ngx.now() 做时间戳，已内置 2 秒容差补偿小时钟偏差
-- 但若服务器间时钟偏差 > TTL，锁将失去互斥性
-- 参数:
--   lock_key: 锁的键名
--   ttl: 锁的过期时间（秒），建议 >= 10s
-- 返回:
--   lock_acquired, lock_val: 是否成功获取锁 + 锁的值（用于安全释放）
local function acquire_distributed_lock(lock_key, ttl)
    if not SH_META then
        return false
    end
    
    ttl = ttl or 10  -- 默认 10 秒
    
    -- 生成锁值：PID:时间戳
    local lock_val = get_worker_pid() .. ":" .. tostring(ngx.now())
    
    -- 尝试获取锁
    local lock_acquired = SH_META:add(lock_key, lock_val, ttl)
    
    -- 如果获取失败，检查是否是过期锁（Worker 崩溃导致）
    if not lock_acquired then
        local old_lock = SH_META:get(lock_key)
        if old_lock and type(old_lock) == "string" then
            -- 解析旧锁的时间戳
            local old_pid, old_time_str = old_lock:match("^(%d+):(%d+%.?%d*)$")
            if old_pid and old_time_str then
                local old_time = tonumber(old_time_str)
                -- 检查锁是否过期（考虑时钟漂移，额外加 2 秒容差）
                if old_time and (ngx.now() - old_time > ttl + 2) then
                    ngx.log(ngx.WARN, string.format(
                        "[WAF] 检测到过期锁 %s (pid=%s, age=%.1fs)，强制释放",
                        lock_key, old_pid, ngx.now() - old_time
                    ))
                    -- 竞态场景：锁在检查过期后、删除前刚好过期，其他 worker 获取了新锁
                    safe_release_distributed_lock(lock_key, old_lock)
                    --  过期锁重试（最多 3 次）：极端并发下其他 worker 可能已抢占
                    for retry = 1, 3 do
                        lock_acquired = SH_META:add(lock_key, lock_val, ttl)
                        if lock_acquired then
                            ngx.log(ngx.WARN, string.format(
                                "[WAF] 过期锁 %s 重试%d次后成功获取", lock_key, retry))
                            break
                        end
                    end
                    if not lock_acquired then
                        ngx.log(ngx.WARN, string.format(
                            "[WAF] 过期锁 %s 重试3次失败，被其他 worker 抢占", lock_key))
                    end
                end
            end
        end
    end
    
    return lock_acquired, lock_val
end

-- 检查IP是否在白名单中（支持CIDR）
local function is_ip_whitelisted(ip)
    if not ip or ip == "" then
        return false
    end

    -- 检查单个IP
    if whitelist_ips[ip] then
        return true
    end
    
    -- 检查CIDR网段
    for _, cidr in ipairs(whitelist_cidrs) do
        if ip_in_cidr(ip, cidr) then
            return true
        end
    end
    
    return false
end

local function load_whitelist_from_file()
    local file, err = io.open(cfg.local_allow_file, "r")
    if not file then
        ngx.log(ngx.ERR, string.format("[WAF] IP白名单文件读取失败: %s，保持旧白名单", err or "unknown error"))
        return false  --  保持旧白名单，不更新
    end

    --  使用 pcall 确保文件一定会被关闭，防止文件描述符泄漏
    local success, result = pcall(function()
        -- 创建新表，不修改原表（原子性保证）
        local new_ips = {
            ["127.0.0.1"] = true,  -- 初始包含本地回环地址
        }
        local new_cidrs = {}

        local ip_count = 1
        local cidr_count = 0
        local invalid_count = 0
        
        for line in file:lines() do
            -- 去除首尾空格和注释
            line = line:gsub("^%s+", ""):gsub("%s+$", "")
            if line ~= "" and not line:find("^#") then
                -- 判断是CIDR还是单个IP
                if line:find("/") then
                    local valid, err_msg = validate_cidr(line)
                    if valid then
                        table.insert(new_cidrs, line)
                        cidr_count = cidr_count + 1
                    else
                        invalid_count = invalid_count + 1
                        ngx.log(ngx.WARN, string.format("[WAF] 跳过无效CIDR: %s (%s)", line, err_msg))
                    end
                else
                    -- 验证单个 IP 格式
                    if ip_to_number(line) then
                        new_ips[line] = true
                        ip_count = ip_count + 1
                    else
                        invalid_count = invalid_count + 1
                        ngx.log(ngx.WARN, string.format("[WAF] 跳过无效IP: %s", line))
                    end
                end
            end
        end

        -- 验证新数据有效性
        if ip_count == 0 and cidr_count == 0 then
            error("白名单数据为空或全部无效")
        end
        
        -- 原子替换：一次性更新所有白名单数据
        whitelist_ips = new_ips
        whitelist_cidrs = new_cidrs
        whitelist_last_refresh = ngx.now()

        -- 报告无效条目数量
        if invalid_count > 0 then
            ngx.log(ngx.WARN, string.format(
                "[WAF] IP白名单加载完成: %d 个IP, %d 个CIDR网段, %d 个无效条目被跳过",
                ip_count, cidr_count, invalid_count
            ))
        else
            ngx.log(ngx.INFO, string.format("[WAF] IP白名单加载成功: %d 个IP, %d 个CIDR网段 (总计: %d)", 
                ip_count, cidr_count, ip_count + cidr_count))
        end
        
        return true
    end)
    
    --  确保文件关闭（无论是否发生错误）
    local close_ok, close_err = pcall(file.close, file)
    if not close_ok then
        ngx.log(ngx.ERR, string.format(
            "[WAF] 关闭白名单文件失败: %s (文件路径: %s)", 
            tostring(close_err), cfg.local_allow_file
        ))
        -- 严重错误时触发告警（可选）
        ngx.log(ngx.ALERT, "[WAF] 白名单文件描述符泄漏风险！")
    end
    
    if not success then
        ngx.log(ngx.ERR, string.format("[WAF] 处理白名单文件时出错: %s，保持旧白名单", result or "unknown"))
        return false
    end
    
    return true
end

--  定时刷新文件白名单（仅在正常模式下）
local function refresh_whitelist_if_needed()
    local current_mode = get_mode()
    if current_mode > 1 then
        return
    end
    
    local now = ngx.now()
    local refresh_interval = cfg.whitelist_refresh_interval or 300
    local global_last_refresh = tonumber(SH_META and SH_META:get("whitelist:last_refresh") or "0") or 0
    
    -- 本地 Worker 的进度落后于全局，或者已经到了标准刷新周期
    if (now - whitelist_last_refresh) >= refresh_interval or (global_last_refresh > whitelist_last_refresh) then
        
        local lock_key = "whitelist:refresh:lock"
        local lock_acquired, lock_val = acquire_distributed_lock(lock_key, 10)

        local ok, err = xpcall(function()
            -- 双重检查：再次从全局共享内存字典核实
            global_last_refresh = tonumber(SH_META and SH_META:get("whitelist:last_refresh") or "0") or 0

            if global_last_refresh > whitelist_last_refresh then
                -- 其他 Worker 已加载最新白名单，直接同步本地时间戳，跳过文件 IO
                whitelist_last_refresh = ngx.now()   
                ngx.log(ngx.DEBUG, "[WAF] 跳过文件 IO，同步其他 Worker 的白名单加载")
            elseif lock_acquired then
                -- 抢到锁的 Worker 负责实际读取文件
                ngx.log(ngx.INFO, "[WAF] 刷新文件白名单到本地 Worker 内存...")
                local success = load_whitelist_from_file()

                if success then
                    whitelist_last_refresh = ngx.now()
                    if SH_META then
                        -- 更新全局共享内存字典记录，通知其他 Worker 跳过文件 IO
                        SH_META:set("whitelist:last_refresh", tostring(ngx.now()), refresh_interval * 2)
                    end
                    ngx.log(ngx.INFO, "[WAF] 本地 Worker 白名单内存同步成功")
                end
            end
        end, function(err_msg)
            ngx.log(ngx.ERR, string.format("[WAF] 白名单刷新异常: %s\n%s", tostring(err_msg), debug.traceback()))
        end)
        if lock_acquired then
            safe_release_distributed_lock(lock_key, lock_val)
        end
    end
end
local function cleanup_redis_data_if_needed()
    if not SH_META then
        return
    end
    
    local now = ngx.now()
    local last_cleanup = tonumber(SH_META:get("redis:cleanup:last_run") or "0")
    
    -- 每24小时执行一次清理（86400秒）
    local cleanup_interval = 86400
    
    if (now - last_cleanup) < cleanup_interval then
        return
    end
    local lock_key = "redis:cleanup:lock"
    local lock_ok, lock_val = acquire_distributed_lock(lock_key, 10)
    if not lock_ok then
        -- 其他 worker 正在清理，跳过
        ngx.log(ngx.DEBUG, "[WAF] Redis清理被锁定，跳过本次清理")
        return
    end
    local ok, err
    local red, conn_err = redis_connect()
    if not red then
        ngx.log(ngx.WARN, "[WAF] Redis 连接失败，跳过清理")
        safe_release_distributed_lock(lock_key, lock_val)
        return
    end

    ok, err = xpcall(function()
        ngx.log(ngx.INFO, "[WAF] 开始定期清理 Redis ZSET 数据...")

        local keys_to_clean = {
            "wf:top:ip",
            "wf:top:uri",
        }

        local cleaned_count = 0
        for _, key in ipairs(keys_to_clean) do
            local ttl_val = red:ttl(key)
            -- 原代码 ttl_val > 0 会跳过 TTL=-1 的持久化键，导致内存泄漏
            if ttl_val and ttl_val >= -1 then
                -- 键存在（包括永久有效的键），检查是否需要清理
                local card = red:zcard(key)
                if card and card > 1000 then
                    -- 如果元素数量超过1000，清理低分元素（保留前1000个）
                    local to_remove = card - 1000
                    if to_remove > 0 then
                        local removed = red:zremrangebyrank(key, 0, to_remove - 1)
                        if removed and removed > 0 then
                            cleaned_count = cleaned_count + removed
                            ngx.log(ngx.INFO, string.format("[WAF] 清理 %s: 删除%d个低分元素 (TTL=%d)", key, removed, ttl_val))
                        end
                    end
                end
            end
        end
        -- daily_key 格式: wf:daily:YYYYMMDD (例如: wf:daily:20260520)
        -- 7天前的 key 应该已经过期，但可能存在未正确设置 TTL 的遗留数据
        local current_date = os.date("%Y%m%d")
        local seven_days_ago = os.date("%Y%m%d", os.time() - 7*86400)

        -- 尝试清理 7-30 天前的 daily_key
        for days_back = 7, 30 do
            local old_date = os.date("%Y%m%d", os.time() - days_back*86400)
            local old_daily_key = "wf:daily:" .. old_date

            -- 检查 key 是否存在
            local exists = red:exists(old_daily_key)
            if exists == 1 then
                -- 获取 TTL，如果没有 TTL 或 TTL 过长，删除它
                local ttl_val = red:ttl(old_daily_key)
                if ttl_val and (ttl_val == -1 or ttl_val > 7*86400) then
                    -- 没有 TTL 或 TTL 超过 7 天，删除
                    red:del(old_daily_key)
                    cleaned_count = cleaned_count + 1
                    ngx.log(ngx.INFO, string.format("[WAF] 清理过期 daily_key: %s (TTL=%d)", old_daily_key, ttl_val))
                end
            end
        end

        -- 更新最后清理时间
        SH_META:set("redis:cleanup:last_run", now, cleanup_interval * 2)

        ngx.log(ngx.INFO, string.format("[WAF] Redis ZSET 清理完成，共清理%d个元素", cleaned_count))
    end, function(err_msg)
        -- 错误处理：记录详细堆栈信息
        ngx.log(ngx.ERR, string.format("[WAF] Redis 清理发生异常: %s\n%s",
            tostring(err_msg), debug.traceback()))
    end)

    --  无论 xpcall 成功或失败，确保释放 Redis 连接（放在 xpcall 外防止异常时泄漏）
    pcall(function() redis_close(red) end)
    safe_release_distributed_lock(lock_key, lock_val)

    if not ok then
        ngx.log(ngx.ERR, "[WAF] Redis 清理失败，锁已释放")
    end
end

--  lua_shared_dict 容量监控：定期检查共享内存使用率，防止写满导致关键数据被 LRU 淘汰
local function monitor_shdict_usage()
    local dicts = {
        { name = "wf_ban_cache", dict = SH_BAN, high_threshold = 0.80, critical_threshold = 0.95 },
        { name = "wf_meta_cache", dict = SH_META, high_threshold = 0.80, critical_threshold = 0.95 },
    }
    for _, d in ipairs(dicts) do
        if d.dict then
            local ok_cap, capacity = pcall(function() return d.dict:capacity() end)
            local ok_free, free = pcall(function() return d.dict:free_space() end)
            if ok_cap and ok_free and capacity and free and capacity > 0 then
                local usage = 1 - (free / capacity)
                if usage >= d.critical_threshold then
                    ngx.log(ngx.ERR, string.format(
                        "[WAF] [SHM_CRITICAL] %s usage=%.1f%% capacity=%d free=%d bytes — 即将写满，LRU 淘汰启动",
                        d.name, usage * 100, capacity, free))
                elseif usage >= d.high_threshold then
                    ngx.log(ngx.WARN, string.format(
                        "[WAF] [SHM_HIGH] %s usage=%.1f%% capacity=%d free=%d bytes — 建议增大 lua_shared_dict 容量",
                        d.name, usage * 100, capacity, free))
                end
            end
        end
    end
end

-- =========================================================
-- 统一日志系统
-- =========================================================
local function get_request_id()
    if ngx.ctx and ngx.ctx.wf_req_id then
        return ngx.ctx.wf_req_id
    end
    
    -- 在 init_worker 等无请求上下文的阶段，ngx.var 可能不可用
    local ok, req_id = pcall(function()
        return ngx.var.request_id
    end)
    
    if ok and req_id then
        return req_id
    end
    return string.format("%.0f-%d-%06d", ngx.now() * 1000, get_worker_pid(), math.random(999999))
end

-- 拦截事件集合（用于日志级别控制：block_request 输出 error 级）
local BLOCK_EVENTS = {
    -- 频率/速率限制
    ["RATE_LIMITED"] = true,
    ["LOCAL_RATE_LIMIT_BLOCKED"] = true,
    ["WP_CRON_RATE_LIMITED"] = true,
    ["LOGGED_USER_WP_ASSET_RATE_LIMITED"] = true,
    -- 登录用户基线检测
    ["LOGGED_USER_PATH_TRAVERSAL"] = true,
    ["LOGGED_USER_QUERY_TOO_LONG"] = true,
    ["LOGGED_USER_RCE_DETECTED"] = true,
    ["LOGGED_USER_ANOMALOUS_UA"] = true,
    -- 缓存绕过
    ["BYPASS_IMMEDIATE_BLOCKED"] = true,
    ["BYPASS_LIMIT_TRIGGERED"] = true,
    -- 通用拦截
    ["INVALID_METHOD"] = true,
    ["PATH_TRAVERSAL_BLOCKED"] = true,
    ["MALICIOUS_PARAM_BLOCKED"] = true,
    ["QUERY_TOO_LONG_BLOCKED"] = true,
    ["RANGE_HEADER_BLOCKED"] = true,
    ["EMPTY_COOKIE_BLOCKED"] = true,
    ["EMPTY_REFERER_BLOCKED"] = true,
    ["XMLRPC_BLOCKED"] = true,
    ["POST_BODY_TOO_LARGE"] = true,
    ["INVALID_CONTENT_TYPE"] = true,
    ["MALICIOUS_FILE_UPLOAD"] = true,
    ["MALICIOUS_POST_BODY"] = true,
    -- 模式/熔断
    ["CIRCUIT_BREAKER_BLOCKED"] = true,
    ["ORIGIN_PROTECT_BLOCKED"] = true,
    ["ATTACK_MODE_BLOCKED"] = true,
    ["DEFEND_MODE_BLOCKED"] = true,
    ["LOCAL_DEFENSE_HIGH_SCORE"] = true,
    ["LOCAL_DEFENSE_EXTENDED_OUTAGE"] = true,
    -- IP封禁
    ["LOCAL_BAN_CACHE_HIT"] = true,
    ["IP_ALREADY_BANNED"] = true,
    ["IP_BANNED_ACCESS"] = true,
    ["IP_BANNED_FEEDBACK"] = true,
    ["ORIGIN_ABUSE_BANNED"] = true,
    -- 白名单保护触发
    ["WHITELIST_BYPASS_BLOCKED"] = true,
    ["ARCHIVES_METHOD_BLOCKED"] = true,
    ["ARCHIVES_ARGS_BLOCKED"] = true,
}

-- 事件名称中文映射
local EVENT_NAMES_CN = {
    -- === 拦截事件 ===
    ["RATE_LIMITED"] = "通用频率限制",
    ["LOCAL_RATE_LIMIT_BLOCKED"] = "本地频率限制拦截",
    ["WP_CRON_RATE_LIMITED"] = "WP-Cron频率限制",
    ["LOGGED_USER_WP_ASSET_RATE_LIMITED"] = "已登录用户WP资产频率限制",
    -- 登录用户检测
    ["LOGGED_USER_PATH_TRAVERSAL"] = "已登录用户路径穿越",
    ["LOGGED_USER_QUERY_TOO_LONG"] = "已登录用户查询过长",
    ["LOGGED_USER_RCE_DETECTED"] = "已登录用户RCE检测",
    ["LOGGED_USER_ANOMALOUS_UA"] = "已登录用户异常UA",
    ["LOGGED_USER_BASELINE_PASS"] = "已登录用户基线通过",
    -- 缓存绕过
    ["BYPASS_IMMEDIATE_BLOCKED"] = "缓存绕过立即拦截",
    ["BYPASS_LIMIT_TRIGGERED"] = "回源绕过限制触发",
    ["BYPASS_STAGE_2_WARNING"] = "回源绕过阶段2警告",
    -- 通用拦截
    ["INVALID_METHOD"] = "非法HTTP方法",
    ["PATH_TRAVERSAL_BLOCKED"] = "路径穿越拦截",
    ["MALICIOUS_PARAM_BLOCKED"] = "恶意参数拦截",
    ["WHITELIST_MALICIOUS_PARAM_BLOCKED"] = "白名单恶意参数拦截",
    ["QUERY_TOO_LONG_BLOCKED"] = "查询过长拦截",
    ["RANGE_HEADER_BLOCKED"] = "Range头拦截",
    ["EMPTY_COOKIE_BLOCKED"] = "空Cookie拦截",
    ["EMPTY_COOKIE_SUSPICIOUS"] = "空Cookie可疑",
    ["EMPTY_REFERER_BLOCKED"] = "空Referer拦截",
    ["XMLRPC_BLOCKED"] = "XML-RPC拦截",
    ["POST_BODY_TOO_LARGE"] = "POST请求体过大",
    ["INVALID_CONTENT_TYPE"] = "非法Content-Type",
    ["MALICIOUS_FILE_UPLOAD"] = "恶意文件上传拦截",
    ["MALICIOUS_POST_BODY"] = "POST请求体恶意内容",
    -- 模式/熔断/防御
    ["CIRCUIT_BREAKER_BLOCKED"] = "熔断器拦截",
    ["ORIGIN_PROTECT_BLOCKED"] = "回源保护拦截",
    ["ATTACK_MODE_BLOCKED"] = "攻击模式拦截",
    ["DEFEND_MODE_BLOCKED"] = "防御模式拦截",
    ["LOCAL_DEFENSE_HIGH_SCORE"] = "本地防御高分拦截",
    ["LOCAL_DEFENSE_EXTENDED_OUTAGE"] = "本地防御长断拦截",
    -- IP封禁
    ["LOCAL_BAN_CACHE_HIT"] = "本地封禁缓存命中",
    ["IP_ALREADY_BANNED"] = "IP已被封禁",
    ["IP_BANNED_ACCESS"] = "已封禁IP访问",
    ["IP_BANNED_FEEDBACK"] = "已封禁IP反馈",
    ["ORIGIN_ABUSE_BANNED"] = "回源滥用封禁",
    -- 白名单相关
    ["WHITELIST_BYPASS_BLOCKED"] = "白名单绕过拦截",
    ["WHITELIST_BYPASS_EMPTY_REFERER"] = "白名单空Referer豁免",
    ["ARCHIVES_METHOD_BLOCKED"] = "归档方法拦截",
    ["ARCHIVES_ARGS_BLOCKED"] = "归档参数拦截",
    ["MALICIOUS_UA_WHITELISTED"] = "白名单IP可疑UA记录",
    -- 白名单管理
    ["WHITELIST_RELOADED"] = "白名单重新加载",
    ["WHITELIST_RELOAD_FAILED"] = "白名单重载失败",
    ["WHITELIST_REFRESH_FAILED"] = "白名单刷新失败",
    ["WHITELIST_ADDED"] = "白名单路径添加",
    ["WHITELIST_REMOVED"] = "白名单路径移除",
    -- UA 检测
    ["SUSPICIOUS_UA_NO_CREDENTIALS"] = "可疑UA无凭证",
    ["SUSPICIOUS_UA_WITH_CREDENTIALS"] = "可疑UA有凭证",
    ["SUSPICIOUS_BOT_DETECTED"] = "可疑Bot检测",
    -- 编码攻击
    ["MULTI_ENCODED_URI_DETECTED"] = "多重编码URI检测",
    ["MULTI_ENCODED_PARAM_DETECTED"] = "多重编码参数检测",
    -- Referer 豁免
    ["API_NO_REFERER_ALLOWED"] = "API无Referer放行",
    ["API_JSON_NO_REFERER"] = "API-JSON无Referer",
    ["API_XML_NO_REFERER"] = "API-XML无Referer",
    ["CORS_NO_REFERER_ALLOWED"] = "CORS无Referer放行",
    -- Redis 事件
    ["REDIS_CIRCUIT_BREAKER_ACTIVE"] = "Redis熔断器激活中",
    ["REDIS_CIRCUIT_BREAKER_TRIGGERED"] = "Redis熔断器触发",
    ["REDIS_CIRCUIT_BREAKER_RESET"] = "Redis熔断器重置",
    ["RESET_CIRCUIT_BREAKER_FAILED"] = "熔断器重置失败",
    ["REDIS_CONNECT_FAILED"] = "Redis连接失败",
    ["REDIS_AUTH_FAILED"] = "Redis认证失败",
    ["REDIS_SELECT_DB_FAILED"] = "Redis选库失败",
    ["REDIS_KEEPALIVE_FAILED"] = "Redis保活失败",
    ["REDIS_PROBE_SUCCESS"] = "Redis探测恢复",
    ["REDIS_PROBE_RETRY"] = "Redis探测重试",
    ["REDIS_PROBE_TIMER_FAILED"] = "Redis探测定时器失败",
    ["REDIS_DOWN_DEGRADE"] = "Redis不可用降级放行",
    -- Redis 评估
    ["HIGH_RISK_REDIS_CHECK"] = "高风险触发Redis检测",
    ["LOW_RISK_SAMPLED"] = "低风险采样放行",
    ["ACCESS_EVAL_FAILED"] = "访问评估Redis失败",
    ["ACCESS_EVAL_EXCEPTION"] = "访问评估脚本异常",
    ["FEEDBACK_EVAL_FAILED"] = "反馈评估Redis失败",
    ["FEEDBACK_EVAL_EXCEPTION"] = "反馈评估脚本异常",
    -- 技术事件
    ["REGEX_PCALL_FAILED"] = "正则匹配异常",
    ["CLUSTER_SCRIPT_FAILED"] = "集群检测脚本失败",
    ["CLUSTER_SCRIPT_EXCEPTION"] = "集群检测脚本异常",
    ["COUNTER_INCR_FAILED"] = "计数器递增失败",
    ["COUNTER_GET_FAILED"] = "计数器读取失败",
    ["COUNTER_SET_FAILED"] = "计数器设置失败",
    -- WordPress
    ["WP_ADMIN_ASSET_SKIP"] = "WP管理后台资产跳过",
    -- 调试
    ["DEBUG"] = "调试信息",
}

-- 日志级别中文映射
local LOG_LEVEL_CN = {
    ["debug"] = "调试",
    ["info"] = "信息",
    ["warn"] = "警告",
    ["error"] = "错误",
}

-- 日志级别常量
local LOG_LEVELS = {debug=1, info=2, warn=3, error=4}

log = function(level, event, ip, uri, details)
    local current_level = cfg.enable_debug_log and 1 or (LOG_LEVELS[cfg.log_level] or 2)
    
    local force_error = false
    local is_block_event = BLOCK_EVENTS[event]
    
    if cfg.force_block_log_error and is_block_event then
        force_error = true
    end
    local level_value = LOG_LEVELS[level] or 2  -- 未定义的级别默认为 notice (2)
    if not force_error and level_value < current_level then
        return  --  提前返回，不执行 string.format
    end

    -- 获取中文事件名（如果有）
    local event_cn = EVENT_NAMES_CN[event] or event
    
    -- 获取中文日志级别
    local level_cn = LOG_LEVEL_CN[level] or level:upper()
    
    --  只在需要时才执行 string.format
    local msg = string.format(
        "[WAF] [%s] [%s] (%s) req_id=%s ip=%s uri=%s %s",
        level_cn,                    -- 中文级别
        event,                       -- 英文事件代码
        event_cn,                    -- 中文事件说明
        get_request_id(),
        ip or "unknown",
        uri or "unknown",
        details or ""
    )

    -- 同时写入 Nginx 错误日志（由 Nginx/rsyslog 异步处理）
    if force_error or level == "error" then
        ngx.log(ngx.ERR, msg)
    elseif level == "warn" then
        ngx.log(ngx.WARN, msg)
    else
        ngx.log(ngx.INFO, msg)
    end

end

local function dlog(...)
    if cfg.enable_debug_log then
        local n = select("#", ...)
        if n == 0 then return end
        local msg = select(1, ...)
        for i = 2, n do
            msg = msg .. select(i, ...)
        end
        log("debug", "DEBUG", nil, nil, msg)
    end
end

-- 精准识别WordPress已登录用户
--  安全加固：不仅检查 cookie 键名，还验证 WordPress 签名 cookie 结构
--    WordPress 登录 cookie 格式：wordpress_logged_in_<HASH>=<user>|<expiry>|<token>|<hmac>
--    攻击者无法伪造 | 分隔的结构化签名值
local function is_logged_user()
    local ok, cookies = pcall(function() return ngx.var.http_cookie end)
    if not ok or not cookies or cookies == "" then
        return false
    end

    --  精确提取 wordpress_logged_in_ cookie 并验证其值结构
    --    防止攻击者发送假 cookie（如 wordpress_logged_in_=fake）通过检查
    local wp_logged_in_start = cookies:find("wordpress_logged_in_", 1, true)
    if wp_logged_in_start then
        -- 提取从匹配位置到分号或结尾的 cookie 值
        local rest = cookies:sub(wp_logged_in_start)
        local eq_pos = rest:find("=", 1, true)
        if eq_pos then
            local end_pos = rest:find(";", eq_pos + 1, true)
            local cookie_val = end_pos and rest:sub(eq_pos + 1, end_pos - 1) or rest:sub(eq_pos + 1)
            -- 🔧 PHP setcookie() 会 urlencode 值，将 | 编码为 %7C
            --    必须先解码再检查管道分隔符（WordPress 签名格式：user|expiry|token|hmac）
            if cookie_val and #cookie_val > 10 then
                local ok_unescape, decoded_val = pcall(ngx.unescape_uri, cookie_val)
                if ok_unescape and decoded_val then
                    --  严格匹配 WordPress 登录 cookie 格式：user|expiry|token|hmac
                    local user, expiry, token, hmac = decoded_val:match("^(.-)|(%d+)|(%w+)|(%x+)$")
                    if user and expiry and token and hmac then
                        return true
                    end
                end
                -- 兼容：部分环境 setcookie 不编码，直接检查原始值中的 |
                local user2, expiry2, token2, hmac2 = cookie_val:match("^(.-)|(%d+)|(%w+)|(%x+)$")
                if user2 and expiry2 and token2 and hmac2 then
                    return true
                end
            end
        end
    end

    -- wordpress_sec_ 是会话 cookie，通常由 WordPress 在登录后设置，可信任
    if cookies:find("wordpress_sec_", 1, true) then
        return true
    end

    -- comment_author_ / woocommerce_items_in_cart 仅为评论者/购物车标识，无签名验证，
    -- 攻击者可轻易伪造以绕过 WAF 检测，仅 wordpress_logged_in_ / wordpress_sec_ 视为已登录
    return false
end
--  自适应递归解码 URI 编码，防御多重编码攻击（如 %2565 -> %65 -> e）
--  log_event: 可选，达到最大迭代次数时的日志事件名（区分 URI 和参数来源）
local function fully_decode(str, log_event)
    if not str or str == "" then
        return str
    end
    log_event = log_event or "MULTI_ENCODED_URI_DETECTED"

    local prev = ""
    local iterations = 0
    local max_iterations = 10  -- 安全上限，实际攻击极少超过 3 层编码

    while prev ~= str and iterations < max_iterations do
        prev = str
        local ok, decoded = pcall(ngx.unescape_uri, str)
        if not ok or not decoded or decoded == str then
            break
        end
        str = decoded
        iterations = iterations + 1
    end

    -- 如果达到最大迭代次数仍未稳定，判定为多层编码攻击，直接返回空字符串触发检测
    if iterations >= max_iterations and prev ~= str then
        log("warn", log_event, nil, nil,
            string.format("iterations=%d (max=%d), possible multi-layer encoding bypass",
                iterations, max_iterations))
        return str  -- 返回当前部分解码值，后续检测将匹配编码后的恶意模式
    end

    return str
end

-- 便捷别名：参数解码（区分日志事件名）。合并自原先独立的 fully_unescape_uri
local function fully_unescape_uri(s)
    return fully_decode(s, "MULTI_ENCODED_PARAM_DETECTED")
end

--  优化：已登录用户行为基线检查
-- 替代原来的"完全豁免"，保留关键安全检查，防止账号被盗后的内部攻击
-- 保留：路径穿越、超长参数、RCE 模式、极端异常 UA
-- 跳过：Redis 评分、采样、SQLi/XSS 正则、熵值计算（成本高，登录用户可信度更高）
local function logged_in_user_baseline_check(ip, uri, args, ua, method, headers)
    --    这些请求的复杂 query string（如 load%5Bchunk_0%5D=...）可能意外触发 RCE 检测
    --    且它们都是 WordPress 核心文件，无需 WAF 基线检查
    --     仅已登录用户可到此（access() 中 is_core_path_exempted 已移除此类路径）
    --     速率限制：防止管理员账号泄露后利用豁免路径做放大攻击
    local is_wp_asset = (uri == "/wp-admin/load-scripts.php"
        or uri == "/wp-admin/load-styles.php"
        or uri == "/wp-admin/admin-ajax.php"
        or uri == "/wp-admin/load-scripts.php/"
        or uri == "/wp-admin/load-styles.php/"
        or uri == "/wp-admin/admin-ajax.php/"
        or starts_with(uri, "/wp-admin/css/")
        or starts_with(uri, "/wp-admin/js/")
        or starts_with(uri, "/wp-admin/images/"))
    if is_wp_asset then
        --  速率限制：即使对已登录用户也限制 WP 资产请求频率
        if SH_META and cfg.logged_user_wp_asset_burst_10s > 0 then
            local asset_burst_key = "wf:wp_asset:burst:" .. ip .. ":10s"
            local asset_slow_key = "wf:wp_asset:slow:" .. ip .. ":60s"
            local asset_burst_n = bump_counter(SH_META, asset_burst_key, 10)
            local asset_slow_n = bump_counter(SH_META, asset_slow_key, 60)
            if asset_burst_n > cfg.logged_user_wp_asset_burst_10s
                or asset_slow_n > cfg.logged_user_wp_asset_slow_60s then
                return block_request("LOGGED_USER_WP_ASSET_RATE_LIMITED", ip, uri,
                    string.format("burst=%d/%d slow=%d/%d",
                        asset_burst_n, cfg.logged_user_wp_asset_burst_10s,
                        asset_slow_n, cfg.logged_user_wp_asset_slow_60s), 429)
            end
        end
        ngx.ctx.wf_skip = true
        ngx.ctx.wf_logged_user = true
        log("info", "WP_ADMIN_ASSET_SKIP", ip, uri, "WP管理后台资产，跳过基线检查")
        return
    end
    if cfg.block_path_traversal then
        local decoded_uri = fully_decode(uri):lower()
        for _, s in ipairs(cfg.path_traversal_signals) do
            if decoded_uri:find(s, 1, true) then
                return block_request("LOGGED_USER_PATH_TRAVERSAL", ip, uri,
                    string.format("decoded=%s signal=%s", decoded_uri, s))
            end
        end
    end
    local qmax = cfg.logged_user_query_hard_limit
    if args and #args > qmax then
        return block_request("LOGGED_USER_QUERY_TOO_LONG", ip, uri,
            string.format("len=%d limit=%d", #args, qmax), 444)
    end
    --    使用已编译的 RCE 组正则，跳过 SQLi/XSS（避免误伤 admin 正常操作）
    if cfg.logged_user_rce_only and args and args ~= "" then
        -- 🔧 pcall 保护 init，防止 regex 编译异常导致 500
        local rce_init_ok, rce_init_err = pcall(init_malicious_params_re)
        if rce_init_ok and malicious_rce_re then
            -- 使用安全匹配，仅检查 RCE 组
            local matched = false
            local ok, err = pcall(function()
                matched = ngx.re.find(args, malicious_rce_re, "joi") ~= nil
            end)
            if ok and matched then
                return block_request("LOGGED_USER_RCE_DETECTED", ip, uri,
                    string.format("rce_pattern_in_args len=%d", #args))
            end
            -- URL 解码后再次检测（防御编码绕过）
            local fully_decoded = fully_unescape_uri(args)
            if fully_decoded ~= args then
                local matched2 = false
                local ok2 = pcall(function()
                    matched2 = ngx.re.find(fully_decoded, malicious_rce_re, "joi") ~= nil
                end)
                if ok2 and matched2 then
                    return block_request("LOGGED_USER_RCE_DETECTED", ip, uri,
                        "rce_pattern_in_decoded_args")
                end
            end
        end
    end
    if ua and ua ~= "" then
        local ua_len = #ua
        if ua_len < 5 then
            return block_request("LOGGED_USER_ANOMALOUS_UA", ip, uri,
                string.format("ua_len=%d (suspiciously short)", ua_len))
        end
        if ua_len > 1000 then
            return block_request("LOGGED_USER_ANOMALOUS_UA", ip, uri,
                string.format("ua_len=%d (abnormally long)", ua_len))
        end
    end

    -- 所有基线检查通过，放行（但标记为「已登录-跳过重检测」）
    ngx.ctx.wf_skip = true
    ngx.ctx.wf_logged_user = true
    log("info", "LOGGED_USER_BASELINE_PASS", ip, uri,
        "已登录用户通过基线检查，跳过 Redis 评分/采样")
end

-- =========================================================
-- 基础请求分类函数
-- =========================================================
-- 模块级静态资源扩展名表（避免每次请求重新创建）
local STATIC_EXT = {
    css = true, js = true, map = true,
    png = true, jpg = true, jpeg = true, gif = true, webp = true, svg = true, ico = true,
    woff = true, woff2 = true, ttf = true, eot = true,
    mp4 = true, mp3 = true, pdf = true,
    avi = true, mov = true, wmv = true, flv = true, mkv = true, webm = true, m4v = true,
}

local function is_static_asset(uri)
    if not uri or uri == "" then
        return false
    end
    local ext = uri:match("%.([%w]+)$")
    if not ext then
        return false
    end
    return STATIC_EXT[ext:lower()] == true
end

local function is_wp_sensitive(uri)
    if not uri or uri == "" then
        return false
    end
    return uri == "/wp-login.php"
        or uri == "/xmlrpc.php"
        or uri == "/wp-register.php"
        or uri == "/wp-lostpassword.php"
end

local function is_wp_api(uri)
    if not uri or uri == "" then
        return false
    end
    return starts_with(uri, "/wp-json/")
        or uri == "/wp-admin/admin-ajax.php"
        or uri == "/wp-sitemap.xml"
end

local function is_core_fast_path(uri)
    if not uri or uri == "" then
        return false
    end
    --  ⚠️ wp-cron.php 已移除（同 is_core_path_exempted 的安全加固）
    --  ⚠️ wp-sitemap.xml 在核心路径豁免中处理
    return uri == "/favicon.ico"
        or uri == "/robots.txt"
        or uri == "/sitemap.xml"
        or uri == "/wp-sitemap.xml"
        or uri == "/atom.xml"
        or uri == "/feed"
        or uri == "/healthz"
end

-- 核心路径豁免函数（识别系统级别的核心路径，这些路径无需WAF检测）
local function is_core_path_exempted(uri)
    if not uri or uri == "" then
        return false
    end
    -- 健康检查路径
    if uri == "/healthz" or uri == "/health" or uri == "/healthy" then
        return true
    end
    -- 系统配置文件路径
    if uri == "/robots.txt" or uri == "/sitemap.xml" or uri == "/wp-sitemap.xml" then
        return true
    end
    -- WordPress 系统任务（对所有用户都可放行）
    -- ⚠️ 安全加固：wp-cron.php 不再对所有用户豁免
    --    仅 localhost 可免检，外部 IP 需要速率限制（防止被利用做回源攻击）
    --    处理逻辑移至 access() 中，通过 is_wp_cron_allowed() 判断
    -- if uri == "/wp-cron.php" then return true end
    -- ⚠️ WP 管理后台资产（load-scripts/load-styles/admin-ajax 等）不在此豁免
    --    已登录用户的豁免 + 速率限制在 logged_in_user_baseline_check() 中处理
    -- Well-Known 标准路径（ACME、WebFinger等）
    if starts_with(uri, "/.well-known/") then
        return true
    end
    -- Apple 系统文件
    if uri == "/.apple-app-site-association" then
        return true
    end
    return false
end

local function is_html_like(uri, method, accept)
    if method ~= "GET" and method ~= "HEAD" then
        return false
    end

    if is_static_asset(uri) or is_wp_api(uri) or is_wp_sensitive(uri) then
        return false
    end

    if uri == "/" or uri == "" or uri == "/index.php" then
        return true
    end

    if uri and uri ~= "" and not uri:find("%.[%w]+$") then
        -- 只匹配明确的 HTML 类型
        if accept and (
            accept:find("text/html", 1, true)
            or accept:find("application/xhtml+xml", 1, true)
        ) then
            return true
        end
    end

    return false
end

-- =========================================================
-- 爬虫与绕过检测
-- =========================================================
local function is_known_good_bot(ua)
    if not ua or ua == "" then
        return false
    end
    local u = ua:lower()
    -- WordPress 内部请求（Action Scheduler、WP-Cron 等），UA 格式：WordPress/X.Y; site_url
    -- 加入白名单防止 admin-ajax.php 等内部请求被 WAF 误拦（如空 Referer 拦截）
    if u:find("wordpress/", 1, true) then
        return true
    end
    -- 合法的监控/检测服务（uptime robot, statuscake, pingdom 等）
    if u:find("uptimerobot", 1, true)
        or u:find("statuscake", 1, true)
        or u:find("pingdom", 1, true)
        or u:find("site24x7", 1, true)
        or u:find("hetrixtools", 1, true) then
        return true
    end
    return u:find("googlebot", 1, true)
        or u:find("bingbot", 1, true)
        or u:find("duckduckbot", 1, true)
        or u:find("yandexbot", 1, true)
        or u:find("applebot", 1, true)
        or u:find("baiduspider", 1, true)
        or u:find("sogou", 1, true)
        or u:find("bytespider", 1, true)
        or u:find("slurp", 1, true)
end

local function looks_suspicious_ua(ua)
    -- 空UA仅标记可疑但不视为恶意（健康检查等合法请求可能无UA）
    if not ua or ua == "" then
        return false
    end
    local ua_len = #ua
    if ua_len < 10 or ua_len > 500 then
        return true
    end

    local u = ua:lower()
    local match_count = 0  --  统计匹配的关键字数量
    
    for _, s in ipairs(cfg.malicious_uas) do
        if u:find(s, 1, true) then
            match_count = match_count + 1
            -- 如果 UA 中包含恶意关键字，且 UA 长度过短（<20），则判定为恶意
            -- 长 UA 即使包含关键字也可能是合法的（如正常浏览器 UA 包含 "java"）
            if ua_len < 20 then
                return true
            end
        end
    end
    
    --  长 UA 如果匹配多个关键字，也更可能是恶意的
    if match_count >= 2 then
        return true
    end

    return false
end

--  优化：预计算熵值查找表，消除热点函数中的 math.log() 调用
-- 二维表结构：ENTROPY_LOOKUP[len][count] = -(count/len) * log(count/len)
-- 字符串长度范围 16~128，字符频次范围 1~len
local ENTROPY_LOOKUP = {}
local LOG_LEN_LOOKUP = {}
for l = 16, 128 do
    ENTROPY_LOOKUP[l] = {}
    LOG_LEN_LOOKUP[l] = math.log(l)
    for c = 1, l do
        local p = c / l
        ENTROPY_LOOKUP[l][c] = -p * math.log(p)
    end
end

local function calc_entropy(args)
    if not args or args == "" then
        return 0
    end

    local len = #args
    
    --  关键优化：缩短阈值，减少 CPU 消耗
    if len < 16 then
        return 0  -- 太短，熵值无意义
    end
    
    if len > 128 then
        return 0.9  -- 直接返回高熵值，避免 CPU 浪费
    end

    local freq = {}
    for i = 1, len do
        local c = args:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end

    -- ✅ 查表替代 math.log(p)：O(1) 直接取值，消除 C 函数调用开销
    local contrib = ENTROPY_LOOKUP[len]
    local entropy = 0
    for _, count in pairs(freq) do
        entropy = entropy + contrib[count]
    end

    -- ✅ 查表替代 math.log(len)
    return entropy / LOG_LEN_LOOKUP[len]
end

-- 正常查询参数键名集合（模块级常量，精确匹配参数名）
local NORMAL_QUERY_KEYS = {
    ["page"] = true, ["paged"] = true, ["p"] = true,
    ["s"] = true, ["preview"] = true, ["cat"] = true,
    ["tag"] = true, ["author"] = true,
}
local function normal_query_allowed(args)
    if not args or args == "" then
        return true
    end
    
    -- 逐个参数检查，只要出现一个不在允许列表里的键就返回 false
    for part in args:gmatch("[^&]+") do
        local eq = part:find("=", 1, true)
        local key = eq and part:sub(1, eq - 1) or part
        
        -- 如果参数不在白名单中，立即返回 false
        if not NORMAL_QUERY_KEYS[key] then
            return false
        end
    end
    
    -- 所有参数都在白名单中，返回 true
    return true
end

-- 全类型缓存绕过检测（带请求级缓存，避免同一请求重复计算）

-- 绕过信号参数键名集合（模块级常量，精确匹配参数名，避免子串误判）
local BYPASS_KEYS = {
    ["_"] = true, ["nocache"] = true, ["no-cache"] = true,
    ["cachebust"] = true, ["cb"] = true, ["t"] = true,
    ["timestamp"] = true, ["random"] = true, ["rnd"] = true,
    ["v"] = true, ["ver"] = true, ["rand"] = true,
}

local function _has_bypass_signals_raw(headers, args, method, uri)
    local ua = tolower(headers["user-agent"] or "")
    if is_known_good_bot(ua) then
        return false
    end

    if args and args ~= "" then
        -- 全字符串关键词（非参数键，直接匹配即可）
        if args:find("nocache", 1, true)
        or args:find("no-cache", 1, true)
        or args:find("cachebust", 1, true) then
            return true
        end

        -- 单次遍历：同时检测bypass键名、value熵值、参数计数
        local param_count = 0
        local has_normal_param = false

        for part in args:gmatch("[^&]+") do
            param_count = param_count + 1
            local eq = part:find("=", 1, true)

            -- 精确匹配参数键名
            local key = eq and part:sub(1, eq - 1) or part
            if BYPASS_KEYS[key] then
                -- v/t/cb 仅在值为长随机串/时间戳时才视为绕过信号，避免误伤正常版本号/参数
                if key == "v" or key == "t" or key == "cb" then
                    local v = eq and part:sub(eq + 1) or ""
                    if #v > 8 and v:match("^%d+$") then
                        return true
                    end
                else
                    return true
                end
            end

            -- value熵值检测
            local v = eq and part:sub(eq + 1) or part
            if #v > 16 then
                local entropy = calc_entropy(v)
                if entropy > 0.7 then
                    return true
                end
            end

            -- 正常参数标记（直接查表，避免再调用normal_query_allowed遍历）
            if not has_normal_param and NORMAL_QUERY_KEYS[key] then
                has_normal_param = true
            end
        end

        if param_count > 8 and not has_normal_param then
            return true
        end
    end
    local cc = tolower(headers["cache-control"] or "")
    local pragma = tolower(headers["pragma"] or "")

    if cc:find("no-cache", 1, true)
    or cc:find("no-store", 1, true)
    or cc:find("max-age=0", 1, true)
    or cc:find("s-maxage=0", 1, true)
    or cc:find("must-revalidate", 1, true)
    or cc:find("proxy-revalidate", 1, true)
    or cc:find("private", 1, true)
    or cc:find("no-transform", 1, true)
    or pragma:find("no-cache", 1, true) then
        return true
    end
    if headers["authorization"] then
        local ok, cookie_val = pcall(function() return ngx.var.http_cookie end)
        local has_cookie = ok and cookie_val ~= nil and cookie_val ~= ""
        local has_referer = (headers["referer"] or "") ~= ""

        if not has_cookie and not has_referer then
            -- 无 Cookie 且无 Referer 的 Authorization 请求，视为绕过
            return true
        end
        -- 有 Cookie 或 Referer 的授权请求，不视为绕过（正常 API 调用）
    end

    -- Range头不作为绕过信号：视频流、PDF查看、断点续传等正常行为

    if headers["x-cache-buster"] 
    or headers["x-plugins-data"] 
    or headers["x-coming-from"]
    or headers["x-random"]
    or headers["x-nocache"]
    or headers["x-timestamp"]
    or headers["x-no-cache"]
    or headers["x-bypass-cache"]
    or headers["x-force-dynamic"]
    or headers["x-cb"] then
        return true
    end

    if method ~= "GET" and method ~= "HEAD" and is_static_asset(uri) then
        return true
    end
    -- 路径穿越有独立的检测步骤（见 access() 第 2105-2113 行）
    local accept = tolower(headers["accept"] or "")
    if accept ~= "" and not accept:find("text/html", 1, true) and not accept:find("application/xhtml", 1, true) and not accept:find("*/*", 1, true) then
        if uri == "/" or uri == "/index.php" or starts_with(uri, "/archives/") then
            return true
        end
    end

    return false
end

local function has_bypass_signals(headers, args, method, uri)
    if ngx.ctx._bypass_result ~= nil then
        return ngx.ctx._bypass_result
    end
    
    local result = _has_bypass_signals_raw(headers, args, method, uri)
    ngx.ctx._bypass_result = result
    return result
end

--  优化：SQLi 预检 — 轻量级字面量扫描，跳过无 SQL 特征的干净请求
-- 仅在 args 包含 SQL 相关字符时才启用 SQLi 正则组（省去约 80%+ 合法流量的正则开销）
local function _has_sqli_literals(s)
    return s:find("'", 1, true)
        or s:find(";", 1, true)
        or s:find("@", 1, true)
        or s:find("select", 1, true)
        or s:find("union", 1, true)
        or s:find("sleep", 1, true)
        or s:find("char(", 1, true)
        or s:find("cast(", 1, true)
end

--  优化：上下文感知分组检测
-- 根据请求特征（uri/method/accept）动态选择启用的规则组：
--   RCE： 始终检测（通用威胁）
--   SQLi：仅在参数含 SQL 特征时检测（预检跳过干净请求）
--   XSS： 仅对 HTML 类端点检测（API/静态资源跳过）
-- 无上下文时降级为全量检测（向后兼容）
local function has_malicious_params(args, uri, method, accept, force_xss)
    if not cfg.block_malicious_params or not args or args == "" then
        return false
    end

    -- 🔧 优化1：ngx.ctx 缓存 — 同一请求内多次调用复用结果
    --    has_malicious_params 被 access()/is_fast_path_request/is_whitelisted_path 等多次调用
    --    缓存命中可省去 6-8 次 ngx.re.find 调用
    --    注：ngx.ctx 请求级生命周期，请求结束自动释放，不会跨请求泄漏
    if ngx.ctx._malicious_result ~= nil then
        return ngx.ctx._malicious_result
    end

    -- 🔧 优化2：最短长度门控 — args < mal_params_min_len 不可能包含恶意特征
    --    例如 "p=1" "s=ab" 等极短参数直接跳过，省去正则编译/匹配开销
    --    阈值 8：最短的有意义恶意模式如 "sleep(" "eval(" "cmd" 接近此长度
    local mal_params_min_len = cfg.malicious_params_min_len or 8
    if #args < mal_params_min_len then
        ngx.ctx._malicious_result = false
        return false
    end

    local rce_re, sqli_re, xss_re = init_malicious_params_re()

    -- 判断是否需要 XSS 检测（force_xss 由白名单路径检测传入，强制全量检查）
    local check_xss = force_xss or (not uri or not method or not accept) or is_html_like(uri, method, accept)

    -- 判断是否需要 SQLi 检测
    local check_sqli = (sqli_re ~= nil) and _has_sqli_literals(args)

    -- ==============================================
    -- Pass 1: 原始参数匹配
    -- ==============================================
    if rce_re and has_malicious_params_safe(args, rce_re) then
        ngx.ctx._malicious_result = true
        return true
    end
    if check_sqli and has_malicious_params_safe(args, sqli_re) then
        ngx.ctx._malicious_result = true
        return true
    end
    if check_xss and xss_re and has_malicious_params_safe(args, xss_re) then
        ngx.ctx._malicious_result = true
        return true
    end

    -- ==============================================
    -- Pass 2: URL 解码后参数匹配（防御多重编码绕过）
    -- 🔧 优化3：若原始参数无 '%' 则无需解码重检，省去 expensive decode + 3组regex
    --    合法流量极少在 query string 中包含 % 编码的恶意模式
    -- ==============================================
    if args:find("%", 1, true) then
        local fully_decoded = fully_unescape_uri(args)
        if fully_decoded ~= args then
            if rce_re and has_malicious_params_safe(fully_decoded, rce_re) then
                ngx.ctx._malicious_result = true
                return true
            end

            -- 对解码后的字符串重新做 SQLi 预检
            if sqli_re and _has_sqli_literals(fully_decoded) then
                if has_malicious_params_safe(fully_decoded, sqli_re) then
                    ngx.ctx._malicious_result = true
                    return true
                end
            end

            if check_xss and xss_re and has_malicious_params_safe(fully_decoded, xss_re) then
                ngx.ctx._malicious_result = true
                return true
            end
        end
    end

    ngx.ctx._malicious_result = false
    return false
end
has_malicious_params_safe = function(args, re_obj)
    args = flatten_value(args)
    
    if not args or args == "" then
        return false
    end

    --  防御正则 DoS：截断超长输入，超过 cfg.malicious_params_regex_max_len 的部分丢弃
    -- 理由：恶意关键字通常在输入前部出现，截断不会降低检出率
    --       但可以防止极端长字符串导致 PCRE 回溯膨胀
    local len = #args
    local max_len = cfg.malicious_params_regex_max_len
    if len > max_len then
        args = args:sub(1, max_len)
    end

    local matched = false
    local ok, err = pcall(function()
        local res, regex_err = ngx.re.find(args, re_obj, "joi")
        if regex_err then
            error("Regex error: " .. tostring(regex_err))
        end
        matched = (res ~= nil)
    end)
    
    if not ok then
        local err_str = tostring(err or "unknown")
        log("error", "REGEX_PCALL_FAILED", nil, nil, 
            string.format("error=%s", err_str))
        return false  -- 正则错误时不匹配，避免阻塞请求
    end
    
    return matched
end

-- =========================================================
-- 异常参数熵值检测
-- =========================================================
local function value_entropy_score(v)
    if not v or v == "" then
        return 0
    end

    local len = #v
    if len < 8 then
        return 0
    end
    
    --  关键优化：超过 64 字符直接判可疑，不再遍历
    if len > 64 then
        return 2  -- 直接返回高分，避免 CPU 浪费
    end

    --  优化：使用 sub() 代替 gmatch("."), 性能提升 30%+
    local seen = {}
    local uniq = 0
    for i = 1, len do
        local c = v:sub(i, i)
        if not seen[c] then
            seen[c] = true
            uniq = uniq + 1
        end
    end

    local ratio = uniq / len
    local score = 0

    if len >= cfg.query_entropy_value_soft_len then
        if ratio >= cfg.query_entropy_ratio_threshold then
            score = score + 1
        end

        if v:find("^[0-9a-fA-F]+$") and len >= 16 then
            score = score + 1
        end

        if v:find("^[A-Za-z0-9%+/=]+$") and len >= 20 then
            score = score + 1
        end
    end

    return score
end

local function query_entropy_score(args)
    if not args or args == "" then
        return 0
    end

    local score = 0
    local len = #args
    
    --  关键优化：长 query string 直接判可疑，不再遍历
    if len > 256 then
        return 4  -- 直接返回高分，跳过所有计算
    end

    if len > cfg.query_entropy_args_hard_len then
        score = score + 2
    elseif len > cfg.query_entropy_args_soft_len then
        score = score + 1
    end

    local token_n = 0
    local noisy_n = 0
    local longest = 0

    for part in args:gmatch("[^&]+") do
        token_n = token_n + 1

        local eq = part:find("=", 1, true)
        local v = eq and part:sub(eq + 1) or part
        local vlen = #v

        if vlen > longest then
            longest = vlen
        end

        noisy_n = noisy_n + value_entropy_score(v)
    end

    if token_n >= cfg.query_entropy_token_soft and longest >= cfg.query_entropy_value_soft_len then
        score = score + 1
    end

    if noisy_n >= 2 then
        score = score + 2
    elseif noisy_n >= 1 then
        score = score + 1
    end

    return score
end

local function cf_trust_score(headers)
    local score = 0

    if headers["cf-ray"] then
        score = score + 2
    end
    if headers["cf-connecting-ip"] and ip_to_number(headers["cf-connecting-ip"]) then
        score = score + 2
    end
    if headers["cf-ipcountry"] then
        score = score + 1
    end
    if headers["cf-visitor"] then
        score = score + 1
    end

    return score
end

local function is_content_page(uri)
    if not uri or uri == "" then
        return false
    end
    return uri == "/" or starts_with(uri, "/archives/")
end

local function is_fast_path_request(uri, method, headers, args, ua, cf_trusted)
    if has_bypass_signals(headers, args, method, uri) then
        return false, nil
    end

    if has_malicious_params(args, uri, method, tolower(headers["accept"] or "")) then
        return false, nil
    end

    if uri == "/wp-login.php" or uri == "/wp-register.php" or uri == "/wp-lostpassword.php" then
        return false, nil
    end
    if is_core_fast_path(uri) then
        return true, "core"
    end

    if is_static_asset(uri) and (method == "GET" or method == "HEAD") then
        return true, "static"
    end

    local accept = headers["accept"] or headers["Accept"] or ""

    if cf_trusted
        and (method == "GET" or method == "HEAD")
        and (
            uri == "/"
            or uri == "/index.php"
            or is_html_like(uri, method, accept)
        )
    then
        return true, "cf-trusted-safe"
    end

    return false, nil
end

-- =========================================================
-- 轻量级请求评分
-- =========================================================
local function light_score_request(uri, method, headers, args, entropy_score)
    local ua = headers["user-agent"] or ""
    local accept = headers["accept"] or ""
    local referer = headers["referer"] or ""
    local ok, cookie_val = pcall(function() return ngx.var.http_cookie end)
    local has_cookie = (ok and cookie_val ~= nil and cookie_val ~= "") and 1 or 0
    local has_referer = referer ~= "" and 1 or 0
    local is_html = is_html_like(uri, method, accept)

    local score = 0

    if has_bypass_signals(headers, args, method, uri) then
        score = score + (cfg.light_score_bypass or 4)
    end

    if entropy_score and entropy_score >= cfg.query_entropy_trigger_score then
        score = score + (cfg.light_score_entropy or 4)
    end

    if is_wp_sensitive(uri) then
        score = score + (cfg.light_score_sensitive or 4)
    end

    if is_html and has_cookie == 1 and has_referer == 1 then
        score = score + (cfg.light_score_html_cookie_referer or -2)
    end

    if method == "POST" and has_referer == 0 then
        score = score + (cfg.light_score_post_no_referer or 3)
    end

    if uri == "/" then
        score = score + (cfg.light_score_homepage or -1)
    end

    if score < 0 then
        score = 0
    end

    return score, is_html
end

-- =========================================================
-- 分布式集群攻击检测
-- =========================================================
local CLUSTER_DETECT_SCRIPT = [[
local ip_key = KEYS[1]
local uri_key = KEYS[2]
local now_ts = tonumber(ARGV[1]) or 0
local ttl = tonumber(ARGV[2]) or 300
local threshold = tonumber(ARGV[3]) or 5
local uri = ARGV[4] or ""
local ip = ARGV[5] or ""

-- IP维度：记录该IP访问过的URI
redis.call('ZADD', ip_key, now_ts, uri)
redis.call('ZREMRANGEBYSCORE', ip_key, 0, now_ts - ttl)  -- 清理超过ttl的旧数据
redis.call('EXPIRE', ip_key, ttl)

-- URI维度：记录访问该URI的IP
redis.call('ZADD', uri_key, now_ts, ip)
redis.call('ZREMRANGEBYSCORE', uri_key, 0, now_ts - ttl)  -- 清理超过ttl的旧数据
redis.call('EXPIRE', uri_key, ttl)

-- 获取计数
local uri_count = redis.call('ZCARD', ip_key)
local ip_count = redis.call('ZCARD', uri_key)

-- 判断是否形成集群攻击
local cluster = 0
if uri_count >= threshold and ip_count >= threshold then
    cluster = 1
end

return {cluster, uri_count, ip_count}
]]

--  优先 EVALSHA 执行（预加载 SHA 避免重复发送脚本），NOSCRIPT 时自动回退 EVAL
local function safe_eval(red, script_tag, script, numkeys, ...)
    --  捕获不定参数为表：内层 pcall 闭包会创建新的函数作用域，
    --    直接写 ... 将引用内层函数的空 varargs，而非外层的真实参数
    local eval_args = {...}
    local sha = sha_cache[script_tag]
    if sha then
        local ok, res, err = pcall(function()
            return red:evalsha(sha, numkeys, unpack(eval_args))
        end)
        if ok and res ~= nil then
            return true, res, nil
        end
        -- EVALSHA 失败：检查是否 NOSCRIPT（脚本丢失），是则回退 EVAL，否则返回错误
        --  pcall 异常时 ok=false, res=异常信息, err=nil；Redis 返回错误时 res=nil, err=ERR信息
        local err_msg
        if not ok then
            err_msg = tostring(res)               -- Lua 异常（超时/断连/空指针等）
        elseif err == nil then
            -- Redis 成功但返回 nil（不是错误），直接交给上层处理
            return true, nil, nil
        else
            err_msg = tostring(err)               -- Redis 返回错误（含 NOSCRIPT）
        end
        if err_msg:find("NOSCRIPT", 1, true) or err_msg:find("noscript", 1, true) then
            sha_cache[script_tag] = nil
            ngx.log(ngx.WARN, "[WAF] EVALSHA NOSCRIPT (", script_tag,
                "), falling back to EVAL, err=", err_msg)
            -- fall through to EVAL fallback
        else
            return false, nil, err_msg
        end
    end
    -- 回退 EVAL：无缓存 SHA 或 NOSCRIPT 后重新加载
    return pcall(function()
        return red:eval(script, numkeys, unpack(eval_args))
    end)
end

local function detect_cluster(red, ip, uri)
    if not red then
        return 0, 0, 0
    end

    local now_ts = ngx.now()
    
    --  优先 EVALSHA 执行集群检测脚本，减少网络传输
    local ok, res, err = safe_eval(red, "cluster", CLUSTER_DETECT_SCRIPT, 2,
        "wf:cluster:ip:" .. ip,
        "wf:cluster:uri:" .. uri,
        now_ts,
        cfg.cluster_ttl,
        cfg.cluster_threshold,
        uri,
        ip
    )
    
    if not ok then
        log("error", "CLUSTER_SCRIPT_EXCEPTION", ip, uri,
            string.format("error=%s", tostring(res)))
        return 0, 0, 0
    end
    
    if not res then
        log("error", "CLUSTER_SCRIPT_FAILED", ip, uri, 
            string.format("error=%s", err or "unknown"))
        return 0, 0, 0
    end
    
    -- 解析结果：{cluster, uri_count, ip_count}
    local cluster = tonumber(res[1]) or 0
    local uri_count = tonumber(res[2]) or 0
    local ip_count = tonumber(res[3]) or 0

    return cluster, uri_count, ip_count
end

-- =========================================================
-- 共享内存原子计数器
-- =========================================================
--  优化：增强并发下的计数原子性
--    - critical=true (核心计数器)：走非原子 get+set 降级（接受微小误差）
--    - critical=false (非核心计数器)：直接返回 0（接受精度损失，避免降级路径开销）
bump_counter = function(dict, key, ttl, critical)  -- 已前向声明 local bump_counter
    if not dict then
        return 0
    end
    
    --  critical 默认 true（向后兼容，默认走完整降级路径）
    if critical == nil then
        critical = true
    end

    -- 主路径：原子 incr（O(1)，无锁）
    local ok, n = pcall(function()
        return dict:incr(key, 1, 0, ttl)
    end)
    
    if ok and n ~= nil then
        return n
    end

    --  重试一次：处理共享内存 OOM 后的瞬时恢复
    -- 线程 A incr 时共享内存满 → 其他线程淘汰旧 key → 线程 A 重试 incr 成功
    ok, n = pcall(function()
        return dict:incr(key, 1, 0, ttl)
    end)
    
    if ok and n ~= nil then
        return n
    end

    --  记录共享内存压力警告（帮助运维发现容量不足）
    log("warn", "COUNTER_INCR_FAILED", nil, nil,
        string.format("key=%s critical=%s incr_failed_twice, shared_dict_may_be_full",
            key, tostring(critical)))

    -- 非核心计数器：放弃准确性，直接返回 0
    if not critical then
        return 0
    end

    -- 核心计数器降级方案：非原子的 get+set（最坏情况下接受小幅度误差）
    local current, err = dict:get(key)
    if err then
        log("error", "COUNTER_GET_FAILED", nil, nil, string.format("key=%s error=%s", key, err))
        return 0
    end

    current = tonumber(current) or 0
    local new_v = current + 1

    local ok2, err2 = dict:set(key, new_v, ttl)
    if not ok2 then
        log("error", "COUNTER_SET_FAILED", nil, nil, string.format("key=%s error=%s", key, err2))
        return current
    end

    return new_v
end

local function current_counter(key)
    if not SH_META then
        return 0
    end
    return tonumber(SH_META:get(key) or 0) or 0
end

local function maybe_escalate_global_modes()
    if not SH_META or not global_mode.auto_mode then
        return
    end
    local ok, miss_n, bypass_n, entropy_n = pcall(function()
        return current_counter("wf:g:miss"), 
               current_counter("wf:g:bypass"),
               current_counter("wf:g:entropy")
    end)
    
    if not ok then
        ngx.log(ngx.ERR, string.format(
            "[WAF] [ERROR] [MODE_SWITCH] 读取全局计数器失败: %s", 
            tostring(miss_n)))
        return
    end
    miss_n = tonumber(miss_n) or 0
    bypass_n = tonumber(bypass_n) or 0
    entropy_n = tonumber(entropy_n) or 0

    local attack_hit =
        (miss_n >= cfg.global_attack_miss_threshold)
        or (bypass_n >= cfg.global_attack_bypass_threshold)
        or (entropy_n >= cfg.global_attack_entropy_threshold)

    local origin_hit =
        (miss_n >= cfg.global_origin_miss_threshold)
        or (bypass_n >= cfg.global_origin_bypass_threshold)
        or (entropy_n >= cfg.global_origin_entropy_threshold)
    if origin_hit then
        set_mode(3, cfg.origin_protect_ttl, ("origin m=%d b=%d e=%d"):format(miss_n, bypass_n, entropy_n))
        return
    end

    if attack_hit then
        set_mode(2, cfg.attack_mode_ttl, ("attack m=%d b=%d e=%d"):format(miss_n, bypass_n, entropy_n))
        return
    end

    local current = get_mode()
    -- 熔断模式(mode=3) -> 攻击模式(mode=2) -> 防御模式(mode=1) -> 正常模式(mode=0)
    if current == 3 then
        --  滞后区间：退出阈值 = 进入阈值 × 70%，避免边界指标震荡导致模式反复切换
        local hysteresis = 0.7
        if miss_n < math.floor(cfg.global_origin_miss_threshold * hysteresis)
           and bypass_n < math.floor(cfg.global_origin_bypass_threshold * hysteresis)
           and entropy_n < math.floor(cfg.global_origin_entropy_threshold * hysteresis) then
            set_mode(2, cfg.attack_mode_ttl, "auto degrade: origin->attack")
            return
        end
    end
    if current == 2 then
        -- 计算60%的阈值作为降级标准
        local low_miss = math.floor(cfg.global_attack_miss_threshold * 0.6)
        local low_bypass = math.floor(cfg.global_attack_bypass_threshold * 0.6)
        local low_entropy = math.floor(cfg.global_attack_entropy_threshold * 0.6)
        
        if miss_n < low_miss and bypass_n < low_bypass and entropy_n < low_entropy then
            -- 所有指标都很低，直接恢复到正常模式
            clear_mode()
            return
        elseif miss_n < cfg.global_attack_miss_threshold 
               and bypass_n < cfg.global_attack_bypass_threshold 
               and entropy_n < cfg.global_attack_entropy_threshold then
            -- 指标低于攻击阈值但仍有一定压力，降级到防御模式
            set_mode(1, cfg.attack_mode_ttl, "auto degrade: attack->defend")
            return
        end
    end
    if current == 1 then
        -- 使用更严格的阈值（40%）来恢复到正常模式
        local very_low_miss = math.floor(cfg.global_attack_miss_threshold * 0.4)
        local very_low_bypass = math.floor(cfg.global_attack_bypass_threshold * 0.4)
        local very_low_entropy = math.floor(cfg.global_attack_entropy_threshold * 0.4)
        
        if miss_n < very_low_miss and bypass_n < very_low_bypass and entropy_n < very_low_entropy then
            clear_mode()
            return
        end
    end
end

local function mark_access_pressure(entropy_score)
    if not SH_META then
        return
    end

    bump_counter(SH_META, "wf:g:req_total", cfg.global_counter_ttl)

    if entropy_score and entropy_score >= cfg.query_entropy_trigger_score then
        bump_counter(SH_META, "wf:g:entropy", cfg.global_counter_ttl)
    end

    -- 🔧 状态指标 Redis 存储（端点启用时，不受 global_counter_ttl 影响）
    if cfg.status_endpoint_enabled then
        local sr = redis_connect()
        if sr then
            pcall(function()
                sr:incr("wf:status:req_total")
                if cfg.status_metrics_ttl_days > 0 then
                    sr:expire("wf:status:req_total", cfg.status_metrics_ttl_days * 86400)
                end
            end)
            redis_close(sr)
        end
    end

    maybe_escalate_global_modes()
end

local function mark_feedback_pressure(is_miss, is_bypass)
    if not SH_META then
        return
    end

    if is_miss then
        bump_counter(SH_META, "wf:g:miss", cfg.global_counter_ttl)
    end

    if is_bypass then
        bump_counter(SH_META, "wf:g:bypass", cfg.global_counter_ttl)
    end

    -- 🔧 状态指标 Redis 存储
    if cfg.status_endpoint_enabled then
        local sr = redis_connect()
        if sr then
            pcall(function()
                if is_miss then
                    sr:incr("wf:status:miss")
                    if cfg.status_metrics_ttl_days > 0 then
                        sr:expire("wf:status:miss", cfg.status_metrics_ttl_days * 86400)
                    end
                end
                if is_bypass then
                    sr:incr("wf:status:bypass")
                    if cfg.status_metrics_ttl_days > 0 then
                        sr:expire("wf:status:bypass", cfg.status_metrics_ttl_days * 86400)
                    end
                end
            end)
            redis_close(sr)
        end
    end

    maybe_escalate_global_modes()
end

-- =========================================================
-- Redis连接池管理
-- =========================================================
local function reset_circuit_breaker()
    if not SH_META then
        return false
    end
    local lock_key = "redis:circuit_breaker:reset_lock"
    local lock_acquired, lock_val = acquire_distributed_lock(lock_key, 10)
    if not lock_acquired then
        -- 其他 worker 正在重置，跳过
        return false
    end
    local ok, err = xpcall(function()
        -- 原子重置（清除失败计数、熔断时间戳、阶梯级别）
        SH_META:set("redis:failures", 0)
        SH_META:delete("redis:circuit_breaker:last_open")
        SH_META:delete("redis:circuit_breaker:level")  -- 🔧 重置阶梯退避级别
        log("info", "REDIS_CIRCUIT_BREAKER_RESET", nil, nil,
            "circuit breaker reset successfully, backoff level cleared, attempting reconnection")
        return true
    end, function(err_msg)
        -- 错误处理：记录详细堆栈信息
        log("error", "RESET_CIRCUIT_BREAKER_FAILED", nil, nil,
            string.format("error=%s\n%s", tostring(err_msg), debug.traceback()))
    end)
    safe_release_distributed_lock(lock_key, lock_val)

    return ok or false
end

--  优化：熔断器快速自愈 — 后台 ngx.timer 定期探测 Redis 连接
--       探测成功立即重置熔断器，无需等待请求流量或 TTL 到期
local circuit_breaker_probe_scheduled = false

local function schedule_circuit_breaker_probe()
    if circuit_breaker_probe_scheduled then
        return  -- 已有探测定时器在运行
    end
    
    --  共享内存全局标记：防止多个 Worker 同时创建探测定时器
    if SH_META then
        if SH_META:get("redis:probe:scheduled") == "1" then
            return  -- 其他 Worker 已在探测
        end
        SH_META:set("redis:probe:scheduled", "1", cfg.redis_probe_interval * 2)
    end
    circuit_breaker_probe_scheduled = true
    
    local ok, err = ngx.timer.at(cfg.redis_probe_interval, function(premature)
        if premature then
            circuit_breaker_probe_scheduled = false
            if SH_META then SH_META:delete("redis:probe:scheduled") end
            return
        end
        
        -- 探测 Redis 连接
        local red = redis:new()
        red:set_timeout(cfg.redis_connect_timeout_ms)
        local conn_ok, _ = red:connect(cfg.redis_host, cfg.redis_port)
        
        if conn_ok then
            -- 认证
            local auth_ok = true
            if cfg.redis_pass and cfg.redis_pass ~= "" then
                auth_ok, _ = red:auth(cfg.redis_pass)
            end
            pcall(function() red:close() end)
            
            if auth_ok then
                -- 探测成功，重置熔断器
                log("info", "REDIS_PROBE_SUCCESS", nil, nil,
                    "background probe succeeded, resetting circuit breaker")
                reset_circuit_breaker()
                circuit_breaker_probe_scheduled = false
                if SH_META then SH_META:delete("redis:probe:scheduled") end
                return
            end
        else
            pcall(function() if red then red:close() end end)
        end
        
        -- 探测失败，检查熔断是否仍然有效
        local failures = tonumber(SH_META and SH_META:get("redis:failures") or "0")
        if failures and failures >= cfg.redis_max_failures then
            -- 熔断仍有效，重新调度下一次探测
            log("info", "REDIS_PROBE_RETRY", nil, nil,
                string.format("probe failed, retrying in %ds", cfg.redis_probe_interval))
            circuit_breaker_probe_scheduled = false
            if SH_META then SH_META:delete("redis:probe:scheduled") end
            schedule_circuit_breaker_probe()
        else
            -- 熔断已被其他方式重置，停止探测
            circuit_breaker_probe_scheduled = false
            if SH_META then SH_META:delete("redis:probe:scheduled") end
        end
    end)
    
    if not ok then
        circuit_breaker_probe_scheduled = false
        if SH_META then SH_META:delete("redis:probe:scheduled") end
        log("error", "REDIS_PROBE_TIMER_FAILED", nil, nil,
            string.format("error=%s", tostring(err or "unknown")))
    end
end

--  提取熔断器触发逻辑（redis_connect 中 conn/auth/select 三处共享）
local function trigger_circuit_breaker()
    if not SH_META then return end
    local failures = bump_counter(SH_META, "redis:failures", cfg.redis_circuit_breaker_ttl)
    if failures ~= cfg.redis_max_failures then return end
    local cb_level = bump_counter(SH_META, "redis:circuit_breaker:level", cfg.redis_circuit_breaker_ttl * 2)
    local cur_ttl = cfg.redis_circuit_breaker_init_ttl
    if cb_level >= 3 then cur_ttl = cfg.redis_circuit_breaker_ttl
    elseif cb_level >= 2 then cur_ttl = cfg.redis_circuit_breaker_init_ttl * 2 end
    SH_META:set("redis:circuit_breaker:last_open", ngx.now(), cur_ttl * 2)
    log("error", "REDIS_CIRCUIT_BREAKER_TRIGGERED", nil, nil,
        string.format("failures=%d level=%d ttl=%ds (step backoff)", failures, cb_level, cur_ttl))
end

redis_connect = function()
    if SH_META then
        local failures = tonumber(SH_META:get("redis:failures") or "0")
        if failures >= cfg.redis_max_failures then
            --  检查熔断状态是否过期，尝试自动恢复
            local last_open = tonumber(SH_META:get("redis:circuit_breaker:last_open") or "0")
            -- 🔧 阶梯退避：根据触发级别计算实际 TTL
            local cb_level = tonumber(SH_META:get("redis:circuit_breaker:level") or "0")
            local effective_ttl = cfg.redis_circuit_breaker_init_ttl  -- 默认 10s
            if cb_level >= 2 then
                effective_ttl = cfg.redis_circuit_breaker_ttl  -- 60s (持续触发)
            elseif cb_level >= 1 then
                effective_ttl = cfg.redis_circuit_breaker_init_ttl * 2  -- 20s
            end
            if last_open == 0 or (ngx.now() - last_open) > effective_ttl then
                local ok = reset_circuit_breaker()
                if not ok then
                    -- 其他 worker 正在重置，跳过本次连接尝试
                    return nil, "circuit_breaker_resetting"
                end
            else
                -- 熔断仍然有效，启动后台探测
                schedule_circuit_breaker_probe()
                log("warn", "REDIS_CIRCUIT_BREAKER_ACTIVE", nil, nil, 
                    string.format("failures=%d level=%d ttl=%ds remaining=%.0fs",
                        failures, cb_level, effective_ttl, effective_ttl - (ngx.now() - last_open)))
                return nil, "circuit_breaker_active"
            end
        end
    end
    
    local red = redis:new()
    -- 🔧 双阶梯超时：connect 短超时快速失败，eval 长超时给 Redis 计算时间
    red:set_timeout(cfg.redis_connect_timeout_ms)

    local ok, err = red:connect(cfg.redis_host, cfg.redis_port)
    -- connect 成功后切换为 eval 超时
    if ok then
        red:set_timeout(cfg.redis_eval_timeout_ms)
    end
    if not ok then
        trigger_circuit_breaker()
        
        log("error", "REDIS_CONNECT_FAILED", nil, nil, 
            string.format("host=%s port=%d error=%s", 
                cfg.redis_host, cfg.redis_port, err or "unknown"))
        return nil, err
    end

    if cfg.redis_pass and cfg.redis_pass ~= "" then
        local ok2, err2 = red:auth(cfg.redis_pass)
        if not ok2 then
            trigger_circuit_breaker()
            
            log("error", "REDIS_AUTH_FAILED", nil, nil, err2 or "unknown")
            pcall(function() red:close() end)
            return nil, err2
        end
    end

    if cfg.redis_db ~= nil then
        local ok3, err3 = red:select(cfg.redis_db)
        if not ok3 then
            trigger_circuit_breaker()
            
            log("error", "REDIS_SELECT_DB_FAILED", nil, nil, 
                string.format("db=%d error=%s", cfg.redis_db, err3 or "unknown"))
            pcall(function() red:close() end)
            return nil, err3
        end
    end
    if SH_META then
        SH_META:delete("redis:failures")
        SH_META:delete("redis:circuit_breaker:last_open")
        SH_META:delete("redis:circuit_breaker:level")  -- 🔧 清除阶梯退避级别
    end
    
    return red
end

redis_close = function(red)
    if not red then
        return
    end
    local ok, err = red:set_keepalive(cfg.redis_keepalive_ms, cfg.redis_keepalive_pool)
    if not ok then
        log("warn", "REDIS_KEEPALIVE_FAILED", nil, nil, err or "unknown")
        pcall(function() red:close() end)
    end
end

-- =========================================================
-- 路径白名单热更新
-- =========================================================
local wl_exact = {}
local wl_prefix = {}
local wl_last_reload = 0

local function merge_whitelist_from_redis()
    local exact = {}
    local prefix = {}

    local default_exact = {
        ["/robots.txt"] = true,
        ["/sitemap.xml"] = true,
        ["/favicon.ico"] = true,
        ["/feed"] = true,
        ["/atom.xml"] = true,
        ["/healthz"] = true,
        ["/wp-sitemap.xml"] = true,
    }

    local default_prefix = {
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/",
        "/.well-known/",
        "/wp-admin/css/",
        "/wp-admin/js/",
        "/wp-admin/images/",
        "/wp-admin/load-scripts.php",
        "/wp-admin/load-styles.php",
        "/archives/",
    }

    for k in pairs(default_exact) do
        exact[k] = true
    end
    for _, p in ipairs(default_prefix) do
        prefix[#prefix + 1] = p
    end

    local red, err = redis_connect()
    if not red then
        log("warn", "WHITELIST_RELOAD_FAILED", nil, nil, 
            "Redis连接失败，使用默认白名单，30秒后重试")
        wl_exact = exact
        wl_prefix = prefix
        wl_last_reload = now() - cfg.whitelist_refresh_interval + 30
        
        local exact_count = 0
        for _ in pairs(exact) do
            exact_count = exact_count + 1
        end
        
        log("info", "WHITELIST_RELOADED", nil, nil, 
            string.format("精确匹配=%d 前缀匹配=%d", exact_count, #prefix))
        return false
    end

    local items = red:smembers("wf:wl:path")
    if items then
        for _, p in ipairs(items) do
            if type(p) == "string" and p ~= "" then
                if p:sub(-1) == "*" then
                    local pp = p:sub(1, -2)
                    if pp ~= "" then
                        prefix[#prefix + 1] = pp
                    end
                else
                    exact[p] = true
                end
            end
        end
    end

    wl_exact = exact
    wl_prefix = prefix
    wl_last_reload = now()

    local exact_count = 0
    for _ in pairs(exact) do
        exact_count = exact_count + 1
    end

    if SH_META then
        SH_META:set("wl_count_exact", exact_count)
        SH_META:set("wl_count_prefix", #prefix)
        SH_META:set("wl_last_reload", wl_last_reload)
    end

    log("info", "WHITELIST_RELOADED", nil, nil, 
        string.format("精确匹配=%d 前缀匹配=%d", exact_count, #prefix))

    redis_close(red)
    return true
end

local function ensure_whitelist_fresh()
    -- 文件白名单只在worker启动时加载一次，不需要定期刷新
    -- 此函数仅用于Redis动态白名单的刷新
    if wl_last_reload == 0 or (now() - wl_last_reload) >= cfg.whitelist_refresh_interval then
        local lock_acquired, lock_val = acquire_distributed_lock("wl:reload_lock", 30)
        if not lock_acquired then
            return
        end
        local ok, err = xpcall(function()
            merge_whitelist_from_redis()
        end, function(err_msg)
            -- 错误处理：记录详细堆栈信息
            log("error", "WHITELIST_REFRESH_FAILED", nil, nil,
                string.format("error=%s\n%s", tostring(err_msg), debug.traceback()))
        end)
        safe_release_distributed_lock("wl:reload_lock", lock_val)
    end
end

-- 安全加固版路径白名单检测
local function is_whitelisted_path(uri, headers, args, method)
    if not uri or uri == "" then
        return false
    end

    if has_bypass_signals(headers, args, method, uri) then
        log("warn", "WHITELIST_BYPASS_BLOCKED", nil, uri, 
            "白名单请求携带缓存绕过信号")
        return false
    end

    if has_malicious_params(args, uri, method, tolower(headers["accept"] or ""), true) then
        log("warn", "WHITELIST_MALICIOUS_PARAM_BLOCKED", nil, uri, 
            "白名单请求携带恶意参数（强制全量检测）")
        return false
    end

    if wl_exact[uri] then
        return true
    end

    for _, p in ipairs(wl_prefix) do
        if starts_with(uri, p) then
            if p == "/archives/" then
                if method ~= "GET" and method ~= "HEAD" then
                    log("warn", "ARCHIVES_METHOD_BLOCKED", nil, uri, 
                        string.format("非法方法: %s", method))
                    return false
                end
                if args and args ~= "" and not normal_query_allowed(args) then
                    log("warn", "ARCHIVES_ARGS_BLOCKED", nil, uri, 
                        string.format("异常参数: %s", args))
                    return false
                end
            end
            return true
        end
    end

    return false
end

-- =========================================================
-- IP获取与本地封禁缓存
-- =========================================================
local function get_client_ip(headers)
    local cf_ip = headers["cf-connecting-ip"]
    if cf_ip and cf_ip ~= "" and ip_to_number(cf_ip) then
        return cf_ip, true
    end

    return ngx.var.remote_addr or "0.0.0.0", false
end

local function get_local_ban_cache(ip)
    return SH_BAN and SH_BAN:get(ip) ~= nil
end

local function set_local_ban_cache(ip, ttl)
    if SH_BAN then
        SH_BAN:set(ip, 1, ttl)
    end
end

local function del_local_ban_cache(ip)
    if SH_BAN then
        SH_BAN:delete(ip)
    end
end

local function is_banned(red, ip)
    if not ip or ip == "" then
        return false, nil
    end
    -- 防止 Redis 中已解封但本地缓存未过期导致的误拦截
    if get_local_ban_cache(ip) then
        if red then
            local key = "wf:ban:" .. ip
            local ok_, v = pcall(function() return red:get(key) end)
            if not ok_ or not v or v == ngx.null then
                -- Redis 中已解封，清除本地缓存
                del_local_ban_cache(ip)
                return false, nil
            end
        end
        -- Redis 不可用时，信任本地缓存（保守策略，宁可误拦不可放过）
        return true, "local-cache"
    end

    if not red then
        return false, nil
    end

    local key = "wf:ban:" .. ip
    local ok_v, v = pcall(function() return red:get(key) end)
    if ok_v and v and v ~= ngx.null then
        local ok_ttl, ttl = pcall(function() return red:ttl(key) end)
        if ok_ttl and ttl and ttl > 0 then
            set_local_ban_cache(ip, math.min(ttl, cfg.local_ban_cache_ttl))
        else
            set_local_ban_cache(ip, cfg.local_ban_cache_ttl)
        end
        return true, "redis"
    end

    return false, nil
end




-- =========================================================
-- Redis原子评分脚本
-- =========================================================
local ACCESS_SCRIPT = [[
local function safe_tonumber(v, default)
    default = default or 0
    if v == nil then return default end
    local n = tonumber(v)
    if n == nil then return default end
    -- 检查是否为有限数字（排除 NaN 和 Inf）
    if n ~= n or n == math.huge or n == -math.huge then return default end
    return n
end

local risk_key   = KEYS[1]
local rep_key    = KEYS[2]
local ban_key    = KEYS[3]
local burst_key  = KEYS[4]
local slow_key   = KEYS[5]
local seen_key   = KEYS[6]
local daily_key  = KEYS[7]
local top_ip_key = KEYS[8]

local base_risk       = safe_tonumber(ARGV[1], 0)
local rep_penalty     = safe_tonumber(ARGV[2], 0)
local rep_bonus       = safe_tonumber(ARGV[3], 0)
local risk_ttl        = safe_tonumber(ARGV[4], 1200)
local seen_ttl        = safe_tonumber(ARGV[5], 300)
local burst_base      = safe_tonumber(ARGV[6], 18)
local slow_base       = safe_tonumber(ARGV[7], 12)
local risk_threshold  = safe_tonumber(ARGV[8], 100)
local rep_threshold   = safe_tonumber(ARGV[9], 20)
local soft_ban_ttl    = safe_tonumber(ARGV[10], 900)
local mid_ban_ttl     = safe_tonumber(ARGV[11], 3600)
local hard_ban_ttl    = safe_tonumber(ARGV[12], 86400)
local risk_decay_ratio = safe_tonumber(ARGV[26], 0.03)

local ip              = ARGV[13] or ""
local uri             = ARGV[14] or ""
local method          = ARGV[15] or "GET"
local has_cookie      = safe_tonumber(ARGV[16], 0)
local has_referer     = safe_tonumber(ARGV[17], 0)
local is_html         = safe_tonumber(ARGV[18], 0)
local is_api          = safe_tonumber(ARGV[19], 0)
local is_auth         = safe_tonumber(ARGV[20], 0)
local is_static       = safe_tonumber(ARGV[21], 0)
local is_bypass       = safe_tonumber(ARGV[22], 0)
local ua_suspicious   = safe_tonumber(ARGV[23], 0)
local is_entropy      = safe_tonumber(ARGV[24], 0)
local is_cluster      = safe_tonumber(ARGV[25], 0)

local risk = safe_tonumber(redis.call("GET", risk_key), 0)
local rep  = safe_tonumber(redis.call("GET", rep_key), 100)

redis.call("SADD", seen_key, uri)
redis.call("EXPIRE", seen_key, seen_ttl)
local uniq_n = redis.call("SCARD", seen_key)

local burst_limit = burst_base + math.floor((rep - 50) / 4)
local slow_limit  = slow_base + math.floor((rep - 50) / 6)

if burst_limit < 8 then burst_limit = 8 end
if burst_limit > 60 then burst_limit = 60 end
if slow_limit < 6 then slow_limit = 6 end
if slow_limit > 40 then slow_limit = 40 end

local burst_n = redis.call("INCR", burst_key)
if burst_n == 1 then
  redis.call("EXPIRE", burst_key, 10)
end

local slow_n = redis.call("INCR", slow_key)
if slow_n == 1 then
  redis.call("EXPIRE", slow_key, 60)
end

local decay = math.floor(risk * risk_decay_ratio)
if decay < 1 and risk > 0 then
  decay = 1
end
risk = risk - decay
if risk < 0 then risk = 0 end

local add = base_risk
local crawler_like = 0
local human_like = 0

if is_entropy == 1 then
  add = add + 15
  rep_penalty = rep_penalty + 3
end

if is_cluster == 1 then
  add = add + 20
  rep_penalty = rep_penalty + 5
end

if has_cookie == 1 then human_like = human_like + 1 else crawler_like = crawler_like + 1 end
if has_referer == 1 then human_like = human_like + 1 else crawler_like = crawler_like + 1 end
if is_html == 1 and has_cookie == 1 and has_referer == 1 and uniq_n <= 15 then
  human_like = human_like + 1
end

if ua_suspicious == 1 then
  crawler_like = crawler_like + 1
end
if is_auth == 1 and has_cookie == 0 then
  crawler_like = crawler_like + 2
end
if is_api == 1 and has_cookie == 0 and uniq_n > 8 then
  crawler_like = crawler_like + 1
end
if is_static == 1 and has_cookie == 0 and uniq_n > 30 then
  crawler_like = crawler_like + 1
end
if is_bypass == 1 then
  crawler_like = crawler_like + 1
end
if method == "POST" and has_referer == 0 then
  crawler_like = crawler_like + 1
end

if crawler_like >= 2 then
  add = add + 6 + math.min(20, math.floor(uniq_n / 2))
  rep_penalty = rep_penalty + 2
elseif human_like >= 2 then
  rep_bonus = rep_bonus + 2
  if add > 0 then
    add = add - 2
  end
end

if burst_n > burst_limit then
  add = add + math.min(30, (burst_n - burst_limit) * 2)
end
if slow_n > slow_limit then
  add = add + math.min(25, (slow_n - slow_limit) * 2)
end

if is_bypass == 1 then
  add = add + 30
  rep_penalty = rep_penalty + 5
end

rep = rep + rep_bonus - rep_penalty
if rep > 100 then rep = 100 end
if rep < 0 then rep = 0 end

risk = risk + add
if risk < 0 then risk = 0 end

redis.call("SET", risk_key, risk, "EX", risk_ttl)
redis.call("SET", rep_key, rep, "EX", risk_ttl)

local banned = 0
local ban_reason = ""
local ban_ttl = 0

if risk >= risk_threshold then
  banned = 1
  ban_reason = "risk"
elseif rep <= rep_threshold then
  banned = 1
  ban_reason = "rep"
end

if banned == 1 then
  if risk >= 160 or rep <= 10 then
    ban_ttl = hard_ban_ttl
  elseif risk >= 120 or rep <= 15 then
    ban_ttl = mid_ban_ttl
  else
    ban_ttl = soft_ban_ttl
  end
  redis.call("SET", ban_key, ban_reason, "EX", ban_ttl)
  if ip ~= "" then
    redis.call("ZINCRBY", top_ip_key, 1, ip)
    redis.call("EXPIRE", top_ip_key, 86400*7)
  end
end

redis.call("HINCRBY", daily_key, "risk", add)
redis.call("HINCRBY", daily_key, "burst", (burst_n > burst_limit) and 1 or 0)
redis.call("HINCRBY", daily_key, "slow", (slow_n > slow_limit) and 1 or 0)
redis.call("HINCRBY", daily_key, "ban", banned)
redis.call("EXPIRE", daily_key, 60*60*24*7)

return {banned, risk, rep, burst_n, slow_n, uniq_n, ban_ttl, ban_reason}
]]

local FEEDBACK_SCRIPT = [[
local function safe_tonumber(v, default)
    default = default or 0
    if v == nil then return default end
    local n = tonumber(v)
    if n == nil then return default end
    if n ~= n or n == math.huge or n == -math.huge then return default end
    return n
end

local risk_key    = KEYS[1]
local rep_key     = KEYS[2]
local ban_key     = KEYS[3]
local miss_key    = KEYS[4]
local bypass_key  = KEYS[5]
local daily_key   = KEYS[6]
local top_uri_key = KEYS[7]
local top_ip_key  = KEYS[8]

local miss_limit   = safe_tonumber(ARGV[1], 8)
local bypass_limit = safe_tonumber(ARGV[2], 8)
local miss_bump    = safe_tonumber(ARGV[3], 15)
local bypass_bump  = safe_tonumber(ARGV[4], 30)
local risk_ttl     = safe_tonumber(ARGV[5], 1200)
local risk_th      = safe_tonumber(ARGV[6], 100)
local rep_th       = safe_tonumber(ARGV[7], 20)
local soft_ban_ttl = safe_tonumber(ARGV[8], 900)
local mid_ban_ttl  = safe_tonumber(ARGV[9], 3600)
local hard_ban_ttl = safe_tonumber(ARGV[10], 86400)

local uri          = ARGV[11] or ""
local ip           = ARGV[12] or ""
local is_miss      = safe_tonumber(ARGV[13], 0)
local is_bypass    = safe_tonumber(ARGV[14], 0)

local risk = safe_tonumber(redis.call("GET", risk_key), 0)
local rep  = safe_tonumber(redis.call("GET", rep_key), 100)

local miss_n = safe_tonumber(redis.call("GET", miss_key), 0)
if is_miss == 1 then
  miss_n = redis.call("INCR", miss_key)
  if miss_n == 1 then
    redis.call("EXPIRE", miss_key, 60)
  end
end

local bypass_n = safe_tonumber(redis.call("GET", bypass_key), 0)
if is_bypass == 1 then
  bypass_n = redis.call("INCR", bypass_key)
  if bypass_n == 1 then
    redis.call("EXPIRE", bypass_key, 60)
  end
end

local add = 0
local hit_miss = 0
local hit_bypass = 0

if is_miss == 1 and miss_n > miss_limit then
  add = add + miss_bump
  hit_miss = 1
end

if is_bypass == 1 and bypass_n > bypass_limit then
  add = add + bypass_bump
  hit_bypass = 1
end

if add > 0 then
  risk = risk + add
  redis.call("SET", risk_key, risk, "EX", risk_ttl)
  rep = rep - 1
  if rep < 0 then rep = 0 end
  redis.call("SET", rep_key, rep, "EX", risk_ttl)
end

local banned = 0
local ban_reason = ""
local ban_ttl = 0

if risk >= risk_th then
  banned = 1
  ban_reason = "cache"
elseif rep <= rep_th then
  banned = 1
  ban_reason = "rep"
end

if banned == 1 then
  if risk >= 160 or rep <= 10 then
    ban_ttl = hard_ban_ttl
  elseif risk >= 120 or rep <= 15 then
    ban_ttl = mid_ban_ttl
  else
    ban_ttl = soft_ban_ttl
  end
  redis.call("SET", ban_key, ban_reason, "EX", ban_ttl)
  if ip ~= "" then
    redis.call("ZINCRBY", top_ip_key, 1, ip)
    redis.call("EXPIRE", top_ip_key, 86400*7)
  end
end

redis.call("HINCRBY", daily_key, "miss", hit_miss)
redis.call("HINCRBY", daily_key, "bypass", hit_bypass)
redis.call("EXPIRE", daily_key, 60*60*24*7)
if uri ~= "" then
  redis.call("ZINCRBY", top_uri_key, 1, uri)
  redis.call("EXPIRE", top_uri_key, 86400*7)
end

return {banned, risk, rep, miss_n, bypass_n, ban_ttl, ban_reason}
]]

-- =========================================================
-- 请求分类与评分
-- =========================================================
local function classify_request(uri, method, headers, args, entropy_score, attack_mode, origin_mode)
    local ua = headers["user-agent"] or ""
    local accept = headers["accept"] or ""
    local referer = headers["referer"] or ""
    local ok, cookie_val = pcall(function() return ngx.var.http_cookie end)
    local has_cookie = (ok and cookie_val ~= nil and cookie_val ~= "") and 1 or 0
    local has_referer = referer ~= "" and 1 or 0
    local is_static = is_static_asset(uri) and 1 or 0
    local is_api = is_wp_api(uri) and 1 or 0
    local is_auth = is_wp_sensitive(uri) and 1 or 0
    local is_html = is_html_like(uri, method, accept) and 1 or 0
    local is_bypass = (has_bypass_signals(headers, args, method, uri) or (entropy_score or 0) >= cfg.query_entropy_trigger_score) and 1 or 0
    local ua_suspicious = looks_suspicious_ua(ua) and 1 or 0

    local rep_bonus = 0
    if has_cookie == 1 and has_referer == 1 and is_html == 1 and is_auth == 0 then
        rep_bonus = rep_bonus + 2
    end

    local risk_add = 0
    local rep_penalty = 0

    if ua_suspicious == 1 then
        risk_add = risk_add + 20
        rep_penalty = rep_penalty + 6
    elseif is_known_good_bot(ua) then
        risk_add = risk_add - 5
    end

    if has_cookie == 0 and has_referer == 0 then
        risk_add = risk_add + 5
        rep_penalty = rep_penalty + 2
    end

    if is_auth == 1 then
        risk_add = risk_add + 20
        rep_penalty = rep_penalty + 5
    elseif is_api == 1 then
        risk_add = risk_add + 8
    end

    if is_bypass == 1 then
        risk_add = risk_add + 30
        rep_penalty = rep_penalty + 5
    end

    if entropy_score and entropy_score > 0 then
        risk_add = risk_add + math.min(12, entropy_score * 4)
        rep_penalty = rep_penalty + math.min(4, entropy_score)
    end

    if attack_mode == 1 and is_bypass == 1 then
        risk_add = risk_add + 6
        rep_penalty = rep_penalty + 1
    end

    if origin_mode == 1 and is_html == 1 and has_cookie == 0 then
        risk_add = risk_add + 4
        rep_penalty = rep_penalty + 1
    end

    if method == "POST" and has_referer == 0 then
        risk_add = risk_add + 4
        rep_penalty = rep_penalty + 2
    end

    -- 复用已计算的entropy_score，避免重复调用calc_entropy
    local is_entropy_attack = (entropy_score or 0) >= cfg.query_entropy_trigger_score

    return {
        risk_add = risk_add,
        rep_penalty = rep_penalty,
        rep_bonus = rep_bonus,
        has_cookie = has_cookie,
        has_referer = has_referer,
        is_static = is_static,
        is_api = is_api,
        is_auth = is_auth,
        is_html = is_html,
        is_bypass = is_bypass,
        ua_suspicious = ua_suspicious,
        is_entropy_attack = is_entropy_attack,
        is_cluster = 0,
    }
end

local function evaluate_access(red, ip, uri, method, flags)
    local day = ngx.today():gsub("-", "")

    local risk_key   = "wf:risk:" .. ip
    local rep_key    = "wf:rep:" .. ip
    local ban_key    = "wf:ban:" .. ip
    local burst_key  = "wf:burst:" .. ip
    local slow_key   = "wf:slow:" .. ip
    local seen_key   = "wf:seen:" .. ip
    local daily_key  = "wf:daily:" .. day
    local top_ip_key = "wf:top:ip"

    local ok, res, err = safe_eval(red, "access", ACCESS_SCRIPT, 8,
        risk_key, rep_key, ban_key, burst_key, slow_key, seen_key, daily_key, top_ip_key,
        flags.risk_add,
        flags.rep_penalty,
        flags.rep_bonus,
        cfg.score_ttl,
        cfg.seen_ttl,
        cfg.base_burst_10s,
        cfg.base_slow_60s,
        cfg.risk_ban_threshold,
        cfg.rep_ban_threshold,
        cfg.ban_soft,
        cfg.ban_mid,
        cfg.ban_hard,
        ip,
        uri,
        method,
        flags.has_cookie,
        flags.has_referer,
        flags.is_html,
        flags.is_api,
        flags.is_auth,
        flags.is_static,
        flags.is_bypass,
        flags.ua_suspicious,
        flags.is_entropy_attack and 1 or 0,
        flags.is_cluster and 1 or 0,
        cfg.risk_decay_ratio
    )

    if not ok then
        log("error", "ACCESS_EVAL_EXCEPTION", ip, uri, tostring(res))
        return nil, "exception: " .. tostring(res)
    end

    if not res then
        log("error", "ACCESS_EVAL_FAILED", ip, uri, err or "unknown")
        return nil, err
    end

    return res
end

local function evaluate_feedback(red, ip, uri, is_miss, is_bypass)
    local day = ngx.today():gsub("-", "")

    local risk_key    = "wf:risk:" .. ip
    local rep_key     = "wf:rep:" .. ip
    local ban_key     = "wf:ban:" .. ip
    local miss_key    = "wf:miss:" .. ip
    local bypass_key  = "wf:bypass:" .. ip
    local daily_key   = "wf:daily:" .. day
    local top_uri_key = "wf:top:uri"
    local top_ip_key  = "wf:top:ip"

    local ok, res, err = safe_eval(red, "feedback", FEEDBACK_SCRIPT, 8,
        risk_key, rep_key, ban_key, miss_key, bypass_key, daily_key, top_uri_key, top_ip_key,
        cfg.miss_window_limit,
        cfg.bypass_window_limit,
        cfg.miss_bump_score,
        cfg.bypass_bump_score,
        cfg.score_ttl,
        cfg.risk_ban_threshold,
        cfg.rep_ban_threshold,
        cfg.ban_soft,
        cfg.ban_mid,
        cfg.ban_hard,
        uri,
        ip,
        is_miss and 1 or 0,
        is_bypass and 1 or 0
    )

    if not ok then
        log("error", "FEEDBACK_EVAL_EXCEPTION", ip, uri, tostring(res))
        return nil, "exception: " .. tostring(res)
    end

    if not res then
        log("error", "FEEDBACK_EVAL_FAILED", ip, uri, err or "unknown")
        return nil, err
    end

    return res
end

-- =========================================================
--  WAF 运行状态端点（需在 cfg 中启用 status_endpoint_enabled）
--  仅允许 status_endpoint_allowed_ips 中的 IP 访问
-- =========================================================
local function handle_waf_status(ip)
    local lines = {}
    local function add(k, v) table.insert(lines, k .. ": " .. tostring(v)) end

    local mode = get_mode()
    local mode_names = { "正常", "防御", "高防", "熔断" }
    add("当前模式", (mode_names[mode + 1] or "未知") .. "(" .. mode .. ")")
    add("自动模式", global_mode.auto_mode and "开启" or "关闭")

    if SH_META then
        add("共享内存", "正常")
        add("模式原因", SH_META:get("wf:mode:last_reason") or "-")
        add("实时统计(10s窗口)", "请求=" .. (tonumber(SH_META:get("wf:g:req_total") or 0))
            .. " Miss=" .. (tonumber(SH_META:get("wf:g:miss") or 0))
            .. " Bypass=" .. (tonumber(SH_META:get("wf:g:bypass") or 0))
            .. " 熵值=" .. (tonumber(SH_META:get("wf:g:entropy") or 0)))
    else
        add("共享内存", "未初始化")
    end

    --  Redis 连接（一次连接读取全部指标 + 检测状态，避免重复握手）
    local redis_metrics = {}
    local display_ttl = cfg.status_metrics_ttl_days > 0 and (cfg.status_metrics_ttl_days .. "天") or "永久"
    local r = redis:new()
    r:set_timeout(200)
    local ok_r = r:connect(cfg.redis_host, cfg.redis_port)
    if ok_r then
        if cfg.redis_pass and cfg.redis_pass ~= "" then
            r:auth(cfg.redis_pass)
        end
        add("Redis状态", "已连接")
        if cfg.redis_pass and cfg.redis_pass ~= "" then
            add("Redis认证", "通过")
        end
        if SH_META then
            add("Redis熔断失败数", tonumber(SH_META:get("redis:failures") or 0))
        end
        -- 读取独立存储指标
        pcall(function()
            redis_metrics.req = tonumber(r:get("wf:status:req_total")) or 0
            redis_metrics.miss = tonumber(r:get("wf:status:miss")) or 0
            redis_metrics.bypass = tonumber(r:get("wf:status:bypass")) or 0
        end)
        r:close()
    else
        add("Redis状态", "不可用")
    end
    add("Redis统计(" .. display_ttl .. "窗口)", "请求=" .. (redis_metrics.req or 0)
        .. " Miss=" .. (redis_metrics.miss or 0)
        .. " Bypass=" .. (redis_metrics.bypass or 0))

    if SH_BAN then
        local banned_ips = {}
        local ok_keys, keys = pcall(function() return SH_BAN:get_keys(100) end)
        if ok_keys and keys then
            for _, k in ipairs(keys) do
                local ok_ttl, ttl = pcall(function() return SH_BAN:ttl(k) end)
                if ok_ttl and ttl and ttl > 0 then
                    table.insert(banned_ips, k .. "(剩余" .. ttl .. "秒)")
                end
            end
        end
        add("本地封禁IP数", #banned_ips)
        add("封禁IP列表", #banned_ips > 0 and table.concat(banned_ips, " ") or "-")
    else
        add("本地封禁IP数", 0)
    end

    add("时间戳", ngx.now())
    add("Worker PID", get_worker_pid())

    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.header["Cache-Control"] = "no-cache, no-store"
    ngx.say(table.concat(lines, "\n"))
    return ngx.exit(200)
end

-- =========================================================
-- Worker初始化
-- =========================================================
function _M.init_worker()
    --  init_worker 中初始化随机种子：避免模块级别调用干扰其他库的随机数状态
    if not math_seeded then
        math.randomseed(ngx.now() * 1000 + get_worker_pid())
        math_seeded = true
    end
    -- 🔍 强制诊断：检查共享内存是否声明
    if SH_META then
        ngx.log(ngx.INFO, "[WAF] DIAG: SH_META=OK wf_meta_cache已声明")
    else
        ngx.log(ngx.ERR, "[WAF] DIAG: SH_META=NIL 缺少lua_shared_dict wf_meta_cache声明!")
    end
    if SH_BAN then
        ngx.log(ngx.INFO, "[WAF] DIAG: SH_BAN=OK wf_ban_cache已声明")
    else
        ngx.log(ngx.ERR, "[WAF] DIAG: SH_BAN=NIL 缺少lua_shared_dict wf_ban_cache声明!")
    end

    -- init_worker 阶段不能使用 log() 函数（因为需要 request_id）
    -- 直接使用 ngx.log
    ngx.log(ngx.INFO, string.format(
        "[WAF] [INFO] [WORKER_INIT] req_id=%s WAF worker启动成功",
        string.format("%.0f-%06d", ngx.now() * 1000, math.random(999999))
    ))
    
    init_malicious_params_re()
    load_whitelist_from_file()
   if SH_META then
    local init_ts = now()          -- 或 ngx.now()
    SH_META:set("whitelist:last_refresh", tostring(init_ts), cfg.whitelist_refresh_interval * 2)
    whitelist_last_refresh = init_ts
    ngx.log(ngx.DEBUG, string.format("[WAF] 白名单初始刷新时间: %d", math.floor(init_ts)))
end

    --  EVALSHA 预加载：启动时向 Redis 注册三个 Lua 脚本，后续用 SHA 调用避免重复传输(~5.5KB)
    local red = redis_connect()
    if red then
        local preload_ok, preload_err = pcall(function()
            sha_cache["access"]   = red:script("LOAD", ACCESS_SCRIPT)
            sha_cache["feedback"] = red:script("LOAD", FEEDBACK_SCRIPT)
            sha_cache["cluster"]  = red:script("LOAD", CLUSTER_DETECT_SCRIPT)
        end)
        if preload_ok then
            ngx.log(ngx.INFO, string.format(
                "[WAF] EVALSHA预加载完成: access=%s feedback=%s cluster=%s",
                sha_cache["access"] or "nil",
                sha_cache["feedback"] or "nil",
                sha_cache["cluster"] or "nil"))
        else
            ngx.log(ngx.WARN, "[WAF] EVALSHA预加载失败，将使用EVAL回退, err=", tostring(preload_err))
        end
        redis_close(red)
    else
        ngx.log(ngx.WARN, "[WAF] Redis不可用，跳过EVALSHA预加载，将使用EVAL回退")
    end
end

-- =========================================================
-- Access阶段核心处理逻辑（终极版）
-- =========================================================
function _M.access()
    -- =========================================================
    --  阶段1：基础豁免与快速放行（开销0-1，90%请求在此结束）
    -- =========================================================

    -- 【1.0】WAF 运行状态端点（最先检查，需在 cfg 启用，仅白名单 IP 可访问）
    if cfg.status_endpoint_enabled and (ngx.var.uri == cfg.status_endpoint_path or ngx.var.uri == cfg.status_endpoint_path .. "/") then
        local status_ip = ngx.var.remote_addr or "0.0.0.0"
        for _, allowed_ip in ipairs(cfg.status_endpoint_allowed_ips) do
            if status_ip == allowed_ip then
                ngx.ctx.wf_skip = true
                return handle_waf_status(status_ip)
            end
        end
        ngx.status = 404
        ngx.say("Not Found")
        return ngx.exit(404)
    end

    -- 【1.1】HTTP方法白名单校验（拦截TRACE/CONNECT等非法方法）
    local req_id = ngx.var.request_id
    if not req_id or req_id == "" then
        req_id = string.format("%.0f-%06d", ngx.now() * 1000, math.random(999999))
    end
    ngx.ctx.wf_req_id = req_id

    local ngx_var = ngx.var
    local uri = ngx_var.uri or "/"
    -- 🔧 获取原始请求 URI（nginx 重写前），用于路径豁免匹配
    --    WordPress 会把 /wp-sitemap.xml 等重写为 /index.php
    --    如果只用 ngx.var.uri，豁免匹配将永远失败
    local request_uri = ngx_var.request_uri or uri
    local original_uri = request_uri:match("^([^%?]*)") or uri -- 去掉 query string
    if original_uri == "" then original_uri = "/" end
    local args = ngx_var.args or ""
    local http_cookie = ngx_var.http_cookie or ""
    local remote_addr = ngx_var.remote_addr or "0.0.0.0"

    -- 获取必要的 header
    local ua = tolower(ngx_var.http_user_agent or "")
    ngx.ctx.wf_ua = ua  --  存入 ctx 供 log 阶段读取，避免 timer 中 request context 失效
    local referer = ngx_var.http_referer or ""
    local accept = ngx_var.http_accept or ""
    local cache_control = ngx_var.http_cache_control or ""
    local pragma = ngx_var.http_pragma or ""
    local authorization = ngx_var.http_authorization or nil
    local range = ngx_var.http_range or nil
    local content_length = ngx_var.content_length or ngx_var.http_content_length or ""
    local content_type = ngx_var.content_type or ngx_var.http_content_type or ""

    -- 获取 Cloudflare 相关 header
    local cf_connecting_ip = ngx_var.http_cf_connecting_ip or nil
    local cf_ray = ngx_var.http_cf_ray or nil
    local cf_ipcountry = ngx_var.http_cf_ipcountry or nil
    local cf_visitor = ngx_var.http_cf_visitor or nil

    -- 获取其他 bypass 相关的 x-* headers
    local x_cache_buster = ngx_var.http_x_cache_buster or nil
    local x_plugins_data = ngx_var.http_x_plugins_data or nil
    local x_coming_from = ngx_var.http_x_coming_from or nil
    local x_random = ngx_var.http_x_random or nil
    local x_nocache = ngx_var.http_x_nocache or nil
    local x_timestamp = ngx_var.http_x_timestamp or nil
    local x_no_cache = ngx_var.http_x_no_cache or nil
    local x_bypass_cache = ngx_var.http_x_bypass_cache or nil
    local x_force_dynamic = ngx_var.http_x_force_dynamic or nil
    local x_cb = ngx_var.http_x_cb or nil
    local headers = {
        ["user-agent"] = ua,
        ["referer"] = referer,
        ["accept"] = accept,
        ["cache-control"] = cache_control,
        ["pragma"] = pragma,
        ["authorization"] = authorization,
        ["range"] = range,
        ["content-length"] = content_length,
        ["content-type"] = content_type,
        ["cf-connecting-ip"] = cf_connecting_ip,
        ["cf-ray"] = cf_ray,
        ["cf-ipcountry"] = cf_ipcountry,
        ["cf-visitor"] = cf_visitor,
        ["x-cache-buster"] = x_cache_buster,
        ["x-plugins-data"] = x_plugins_data,
        ["x-coming-from"] = x_coming_from,
        ["x-random"] = x_random,
        ["x-nocache"] = x_nocache,
        ["x-timestamp"] = x_timestamp,
        ["x-no-cache"] = x_no_cache,
        ["x-bypass-cache"] = x_bypass_cache,
        ["x-force-dynamic"] = x_force_dynamic,
        ["x-cb"] = x_cb,
        ["origin"] = ngx_var.http_origin or "",
    }

    local ip = get_client_ip(headers)
    if not ip or ip == "" then
        ip = remote_addr
    end

    local method = ngx.req.get_method()

    -- HTTP方法白名单
    if not cfg.allowed_http_methods[method] then
        return block_request("INVALID_METHOD", ip, uri, string.format("方法: %s", method), 405)
    end

    -- 【1.3】白名单IP/CIDR豁免（支持本地文件+Redis动态白名单）
    if is_ip_whitelisted(ip) then
        ngx.ctx.wf_skip = true
        ngx.log(ngx.INFO, string.format("[WAF] [白名单豁免] ip=%s uri=%s 方法=%s", ip, uri, method))
        return
    end

    -- 【1.3】wp-cron.php 安全控制（防止利用 WordPress 计划任务做回源攻击）
    --        localhost/内网 IP：直接放行（正常的服务器内部调用）
    --        外部 IP：速率限制（1次/10s），超限返回 429
    -- 🔧 使用 original_uri 而非 uri，防止 WordPress 重写后匹配失败
    if original_uri == "/wp-cron.php" then
        local is_local = (ip == "127.0.0.1" or ip == "::1"
            or ip_in_cidr(ip, "10.0.0.0/8")
            or ip_in_cidr(ip, "192.168.0.0/16")
            or ip_in_cidr(ip, "172.16.0.0/12"))
        if is_local then
            ngx.ctx.wf_skip = true
            return
        end
        -- 外部 IP：速率限制
        if SH_META then
            local cron_burst_n = bump_counter(SH_META, "wf:wp_cron:burst:" .. ip .. ":10s", 10)
            if cron_burst_n > 1 then
                return block_request("WP_CRON_RATE_LIMITED", ip, uri,
                    string.format("burst=%d limit=1/10s", cron_burst_n), 429)
            end
        end
        ngx.ctx.wf_skip = true
        return
    end

    -- 【1.4】核心路径豁免（优先于用户身份检查，仅系统级路径：健康检查/robots等）
    -- 🔧 使用 original_uri（重写前），防止 WordPress 重写后匹配失败
    if is_core_path_exempted(original_uri) then
        ngx.ctx.wf_skip = true
        return
    end

    -- 【1.5】已登录用户分层保护（替代完全豁免，保留基础安全检查）
    if is_logged_user() then
        if cfg.logged_user_enable then
            --  新版：分层基线检查（路径穿越/RCE/长度/UA）
            -- 🔧 使用 original_uri 做WP资产路径匹配
            logged_in_user_baseline_check(ip, original_uri, args, ua, method, headers)
            return
        end
        -- 旧版：完全豁免（cfg.logged_user_enable=false 时保留）
        ngx.ctx.wf_skip = true
        return
    end

    -- 刷新白名单
    refresh_whitelist_if_needed()
    ensure_whitelist_fresh()

    -- 获取CF信任评分
    local cf_score = cf_trust_score(headers)
    local cf_trusted = cf_score >= 4

    -- 【1.6】Fast Path快速放行
    -- 🔧 使用 original_uri 做路径匹配，防止 WordPress 重写后豁免失效
    local fast_hit, fast_reason = is_fast_path_request(original_uri, method, headers, args, ua, cf_trusted)
    if fast_hit then
        if fast_reason == "static" and cfg.enable_waf_cache_headers then
            ngx.header["Cache-Control"] = "public, max-age=2592000, immutable"
            ngx.header["X-Cache-Status"] = "static-fast-path"
            ngx.header["Expires"] = ngx.http_time(ngx.time() + 2592000)
        elseif fast_reason == "core" and cfg.enable_waf_cache_headers then
            ngx.header["Cache-Control"] = "public, max-age=3600"
            ngx.header["X-Cache-Status"] = "core-fast-path"
        end
        ngx.ctx.wf_skip = true
        return
    end

    -- 【1.7】全局熔断模式（全局级最高优先级）
    local current_mode = get_mode()

    if current_mode >= 3 and not is_static_asset(uri) and not is_whitelisted_path(uri, headers, args, method) then
        if not is_content_page(uri) then
            log("warn", "CIRCUIT_BREAKER_BLOCKED", ip, uri, string.format("mode=%d", current_mode))
            ngx.ctx.wf_skip = true
            return ngx.exit(444)
        end
    end

    -- 提前获取 bypass_signal，供后续多处使用
    local bypass_signal = has_bypass_signals(headers, args, method, uri)

    -- =========================================================
    --  阶段2：纯内存硬拦截（开销1-2，无任何IO，快速拦截明确攻击）
    -- =========================================================

    -- 【2.1】路径穿越检测（递归URL解码，防御多重编码绕过）
    if cfg.block_path_traversal then
        local decoded_uri = fully_decode(uri):lower()
        for _, s in ipairs(cfg.path_traversal_signals) do
            if decoded_uri:find(s, 1, true) then
                --  添加：白名单检查保护
                if not is_ip_whitelisted(ip) then
                    return block_request("PATH_TRAVERSAL_BLOCKED", ip, uri,
                        string.format("decoded=%s, signal=%s", decoded_uri, s))
                else
                    ngx.log(ngx.INFO, string.format("[WAF] [白名单豁免] PATH_TRAVERSAL规则豁免 ip=%s uri=%s", ip, uri))
                end
            end
        end
    end

    -- 【2.2】恶意参数检测（预编译正则+智能边界匹配，避免ReDoS）
    if has_malicious_params(args, uri, method, accept) then
        --  添加：白名单检查保护
        if not is_ip_whitelisted(ip) then
            return block_request("MALICIOUS_PARAM_BLOCKED", ip, uri, string.format("args=%s", args))
        else
            ngx.log(ngx.INFO, string.format("[WAF] [白名单豁免] MALICIOUS_PARAM规则豁免 ip=%s uri=%s", ip, uri))
        end
    end

    -- 【2.3】超长参数拦截（全局硬限制，快速拦截垃圾请求）
    if args and #args > cfg.global_query_hard_limit then
        --  添加：白名单检查保护
        if not is_ip_whitelisted(ip) then
            return block_request("QUERY_TOO_LONG_BLOCKED", ip, uri,
                string.format("len=%d limit=%d", #args, cfg.global_query_hard_limit), 444)
        else
            ngx.log(ngx.INFO, string.format("[WAF] [白名单豁免] QUERY_TOO_LONG规则豁免 ip=%s uri=%s", ip, uri))
        end
    end

    -- 【2.4】UA检测（纯字符串匹配，拦截curl/wget/sqlmap等扫描器）
    if ua ~= "" and looks_suspicious_ua(ua) then
        if is_ip_whitelisted(ip) then
            log("warn", "MALICIOUS_UA_WHITELISTED", ip, uri, string.format("ua=%s (白名单IP仅记录)", ua))
        else
            local has_cookie = (ngx_var.http_cookie ~= nil and ngx_var.http_cookie ~= "")
            local has_referer = (headers["referer"] or "") ~= ""

            if not has_cookie and not has_referer then
                log("warn", "SUSPICIOUS_UA_NO_CREDENTIALS", ip, uri,
                    string.format("ua=%s, no cookie, no referer", ua))
            else
                log("info", "SUSPICIOUS_UA_WITH_CREDENTIALS", ip, uri,
                    string.format("ua=%s, has_cookie=%s, has_referer=%s",
                        ua, has_cookie and "yes" or "no", has_referer and "yes" or "no"))
            end
        end
    end

    -- 【2.5】全局洪水检测（共享内存全局计数器，拦截最致命的DDoS）
    local global_req_total = bump_counter(SH_META, "wf:g:req_total", 10)
    if global_req_total > cfg.global_req_flood_threshold then
        set_mode(3, cfg.origin_protect_ttl, "全局请求洪水: " .. global_req_total)
    end

    -- 【2.6】本地频率限制（仅对动态请求生效，避免误伤静态资源）
    if cfg.enable_local_rate_limit and not is_static_asset(uri) then
        local rate_limit_keys = {"wf:local:burst:ip:" .. ip}
        local uri_hash = ngx.md5(uri)
        table.insert(rate_limit_keys, "wf:local:burst:ip_uri:" .. ip .. ":" .. uri_hash:sub(1, 8))

        local burst_counts = {}
        local slow_counts = {}
        local max_burst = 0
        local max_slow = 0

        for _, key in ipairs(rate_limit_keys) do
            local burst_n = bump_counter(SH_META, key .. ":10s", 10)
            local slow_n = bump_counter(SH_META, key .. ":60s", 60)
            burst_counts[key] = burst_n
            slow_counts[key] = slow_n

            if burst_n > max_burst then max_burst = burst_n end
            if slow_n > max_slow then max_slow = slow_n end
        end

        local should_block = false
        local block_reason = nil

        for _, key in ipairs(rate_limit_keys) do
            local burst_n = burst_counts[key] or 0
            local slow_n = slow_counts[key] or 0

            if burst_n > cfg.base_burst_10s * 2 or slow_n > cfg.base_slow_60s * 2 then
                should_block = true
                block_reason = string.format("rate_limit_exceeded burst=%d slow=%d", burst_n, slow_n)
                break
            end
        end

        if should_block then
            log("warn", "LOCAL_RATE_LIMIT_BLOCKED", ip, uri,
                string.format("burst=%d slow=%d reason=%s", max_burst, max_slow, block_reason))
            ngx.ctx.wf_skip = true
            return ngx.exit(429)
        end
    end

    -- 【2.7】Range头拦截（非静态资源禁止Range，避免资源耗尽）
    local range_hdr = headers["range"] or headers["Range"]
    if range_hdr and not is_static_asset(uri) then
        return block_request("RANGE_HEADER_BLOCKED", ip, uri, string.format("range=%s", range_hdr))
    end

    -- 【2.8】缓存绕过立即拦截（非静态资源的nocache信号直接拦截）
    --  首次访问豁免：无Cookie且无Referer的请求不立即拦截，降级到阶段3渐进式处理
    --    避免新用户首次访问（地址栏回车/F5刷新/书签进入）被误拦
    if cfg.bypass_block_immediately and bypass_signal and not is_static_asset(uri) then
        local has_cookie = http_cookie ~= nil and http_cookie ~= ""
        local has_referer = (referer or "") ~= ""
        if has_cookie or has_referer then
            return block_request("BYPASS_IMMEDIATE_BLOCKED", ip, uri, "缓存绕过信号")
        end
        -- 首次访问无Cookie无Referer → 不立即拦截，由阶段3.1渐进式处理
    end

    -- 定期清理Redis数据，防止内存泄漏
    cleanup_redis_data_if_needed()
    monitor_shdict_usage()

    -- =========================================================
    --  阶段3：上下文智能拦截（开销2-3，需要请求上下文判断）
    -- =========================================================

    -- 【3.1】回源绕过检测与渐进式拦截（仅统计HTML类请求）
    if is_html_like(uri, method, accept) and bypass_signal then
        local bypass_key = "wf:bypass:" .. ip
        local bypass_count = bump_counter(SH_META, bypass_key, 60)

        if bypass_count > cfg.bypass_limit_per_ip_60s then
            log("warn", "BYPASS_LIMIT_TRIGGERED", ip, uri,
                string.format("count=%d limit=%d method=%s", bypass_count, cfg.bypass_limit_per_ip_60s, method))
            ngx.ctx.wf_skip = true
            return ngx.exit(429)
        end

        -- 阶段式策略：首次容忍 → 强制缓存 → 警告 → 拦截
        if bypass_count == 1 then
            -- 首次绕过信号仅记录，不惩罚：避免用户 F5 刷新 / 初次访问被误伤
            dlog(string.format("首次绕过信号，观察中: ip=%s count=%d", ip, bypass_count))
        elseif bypass_count >= 4 and bypass_count < 9 then
            dlog(string.format("回源阶段1: 强制缓存 count=%d (将在放行时设置)", bypass_count))
        elseif bypass_count >= 9 and bypass_count < 16 then
            log("warn", "BYPASS_STAGE_2_WARNING", ip, uri,
                string.format("count=%d stage=warning (将在放行时设置)", bypass_count))
        end
    end

    -- 【3.2】空Cookie智能拦截（多维度联合判断）
    if cfg.block_empty_cookie and (http_cookie == nil or http_cookie == "") then
        local accept_hdr = headers["accept"] or headers["Accept"] or ""
        if is_html_like(uri, method, accept_hdr) then
            -- CF信任信号判断
            if cf_trusted then
                dlog(string.format("CF信任的无Cookie请求: ip=%s cf_score=%d", ip, cf_score))
            else
                -- UA类型检查
                local ua_is_browser = false
                if ua ~= "" then
                    if ua:find("mozilla") or ua:find("chrome") or ua:find("safari") or
                       ua:find("firefox") or ua:find("edge") or ua:find("opera") then
                        ua_is_browser = true
                    end
                end

                -- URI熵值检查
                local uri_entropy = 0
                if not is_static_asset(uri) then
                    uri_entropy = calc_entropy(uri)
                end
                local uri_is_normal = uri_entropy < 0.7

                -- Cache状态检查
                local cache_status = ngx_var.upstream_cache_status or ""
                local has_cache = cache_status == "HIT" or cache_status == "EXPIRED" or
                                 cache_status == "STALE" or cache_status == "UPDATING"

                -- 频率检查（非核心计数器：incr 失败时跳过，避免非原子 get+set 开销）
                local empty_cookie_count = bump_counter(SH_META, "wf:empty_cookie:" .. ip, 60, false)

                -- 综合评分
                local suspicious_score = 0
                if not cf_trusted then suspicious_score = suspicious_score + 2 end
                if not ua_is_browser then suspicious_score = suspicious_score + 2 end
                if not uri_is_normal then suspicious_score = suspicious_score + 2 end
                if not has_cache then suspicious_score = suspicious_score + 1 end
                if empty_cookie_count > 5 then
                    suspicious_score = suspicious_score + 3
                elseif empty_cookie_count > 3 then
                    suspicious_score = suspicious_score + 1
                end

                -- 决策逻辑
                if suspicious_score >= 7 then
                    return block_request("EMPTY_COOKIE_BLOCKED", ip, uri,
                        string.format("score=%d count=%d cf=%d ua_browser=%s entropy=%.2f cache=%s",
                            suspicious_score, empty_cookie_count, cf_score,
                            ua_is_browser and "yes" or "no", uri_entropy, cache_status or "none"))
                elseif suspicious_score >= 4 then
                    log("warn", "EMPTY_COOKIE_SUSPICIOUS", ip, uri,
                        string.format("score=%d count=%d cf=%d ua_browser=%s entropy=%.2f",
                            suspicious_score, empty_cookie_count, cf_score,
                            ua_is_browser and "yes" or "no", uri_entropy))
                end
            end
        end
    end

    -- 【3.3】空Referer拦截（仅针对POST请求，豁免API/JSON/CORS）
    if cfg.block_empty_referer and method == "POST" and referer == "" then
        --  添加：二次白名单检查保护（防止白名单IP被误拦截）
        if is_ip_whitelisted(ip) then
            ngx.log(ngx.INFO, string.format("[WAF] [二次白名单豁免] EMPTY_REFERER_BLOCKED规则豁免 ip=%s uri=%s", ip, uri))
            log("info", "WHITELIST_BYPASS_EMPTY_REFERER", ip, uri, "白名单IP豁免")
        else
            local has_auth = (headers["authorization"] or "") ~= ""
            local content_type_str = tolower(headers["content-type"] or "")
            local is_json = content_type_str:find("application/json", 1, true) ~= nil
            local is_xml = content_type_str:find("application/xml", 1, true) ~= nil or
                          content_type_str:find("text/xml", 1, true) ~= nil
            local is_cors = (headers["origin"] or "") ~= ""

            if has_auth then
                log("info", "API_NO_REFERER_ALLOWED", ip, uri, string.format("method=%s", method))
            elseif is_json then
                log("info", "API_JSON_NO_REFERER", ip, uri, string.format("content-type=%s", content_type_str))
            elseif is_xml then
                log("info", "API_XML_NO_REFERER", ip, uri, string.format("content-type=%s", content_type_str))
            elseif is_cors then
                log("info", "CORS_NO_REFERER_ALLOWED", ip, uri,
                    string.format("origin=%s", headers["origin"] or headers["Origin"]))
            else
                return block_request("EMPTY_REFERER_BLOCKED", ip, uri, "POST请求无Referer且无API特征")
            end
        end
    end

    -- 【3.4】XMLRPC拦截（WordPress专属攻击点）
    if cfg.block_xmlrpc and uri == "/xmlrpc.php" then
        --  添加：白名单检查保护
        if not is_ip_whitelisted(ip) then
            return block_request("XMLRPC_BLOCKED", ip, uri)
        else
            ngx.log(ngx.INFO, string.format("[WAF] [白名单豁免] XMLRPC规则豁免 ip=%s uri=%s", ip, uri))
        end
    end

    -- 【3.5】POST请求综合限制
    if method == "POST" then
        -- Body大小限制
        local content_length_num = tonumber(headers["content-length"] or headers["Content-Length"] or "0") or 0
        if content_length_num > 1024 * 1024 then
            return block_request("POST_BODY_TOO_LARGE", ip, uri, string.format("size=%d bytes", content_length_num), 413)
        end

        -- Content-Type白名单
        local content_type_lower = tolower(headers["content-type"] or "")
        if content_type_lower ~= "" then
            local allowed_types = {
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "application/json",
                "text/xml",
            }
            local is_allowed = false
            for _, t in ipairs(allowed_types) do
                if content_type_lower:find(t, 1, true) then
                    is_allowed = true
                    break
                end
            end
            if not is_allowed then
                return block_request("INVALID_CONTENT_TYPE", ip, uri, string.format("type=%s", content_type_lower), 415)
            end
        end

        -- 恶意文件上传检测
        if content_type_lower:find("multipart/form-data", 1, true) then
            ngx.req.read_body()
            local body = get_secure_body_data()

            if body and #body > 0 then
                local b = body:lower()

                if b:find('filename="', 1, true) or b:find("filename*=", 1, true) then
                    local decoded_body = fully_decode(body)
                    if decoded_body ~= body then
                        b = decoded_body:lower()
                    end

                    local is_malicious = false
                    local extensions = {"php", "jsp", "asp", "aspx", "exe", "sh", "py", "pl", "cgi", "phtml", "phar", "js", "htaccess", "config", "dll"}
                    for _, ext in ipairs(extensions) do
                        if b:find('filename="[^"]*%.' .. ext .. '[^"]*"', 1) then
                            is_malicious = true
                            break
                        end
                        if b:find("filename*=%w+%'%*[^']*%." .. ext .. "[^']*", 1) then
                            is_malicious = true
                            break
                        end
                    end

                    if is_malicious then
                        return block_request("MALICIOUS_FILE_UPLOAD", ip, uri, "禁止上传脚本文件")
                    end
                end
            end
        end

        -- POST Body恶意内容检测
        if cfg.block_malicious_params and (
            content_type_lower:find("application/x-www-form-urlencoded", 1, true) or
            content_type_lower:find("application/json", 1, true)
        ) then
            ngx.req.read_body()
            local body = get_secure_body_data()

            if body and #body > 0 then
                local check_str = body

                -- 对 form-urlencoded 格式进行解码
                if content_type_lower:find("application/x-www-form-urlencoded", 1, true) then
                    local ok, decoded = pcall(ngx.unescape_uri, body)
                    if ok and decoded then
                        check_str = decoded
                    end
                end
                -- JSON 中的特殊字符可能已 URL 编码，需要解码后检测
                local fully_decoded = fully_decode(check_str)
                if fully_decoded ~= check_str then
                    check_str = fully_decoded
                end

                if has_malicious_params(check_str, uri, method, accept) then
                    return block_request("MALICIOUS_POST_BODY", ip, uri, string.format("body_len=%d, content_type=%s", #body, content_type_lower))
                end
            end
        end

        -- POST频率限制
        local is_logged = is_logged_user()

        if is_logged then
            local post_burst_key = "wf:post:burst:logged:" .. ip
            local post_burst_n = bump_counter(SH_META, post_burst_key, 60, false)  -- 非核心
            if post_burst_n > cfg.logged_user_post_burst_limit then
                return rate_limit_block(ip, uri, string.format("count=%d/60s limit=%d (已登录)", post_burst_n, cfg.logged_user_post_burst_limit))
            end
        else
            -- 🔧 admin-ajax.php 是 WordPress 前端交互入口（评论/点赞/浏览量）
            --    正常页面可能同时触发 2-3 个 AJAX POST，需要更宽松的限制
            local post_limit = 10
            local post_window = 10
            if uri == "/wp-admin/admin-ajax.php" or uri == "/wp-admin/admin-ajax.php/" then
                post_limit = 30   -- admin-ajax 放宽到 30次/10s
                post_window = 10
            end
            local post_burst_key = "wf:post:burst:" .. ip
            local post_burst_n = bump_counter(SH_META, post_burst_key, post_window, false)  -- 非核心
            if post_burst_n > post_limit then
                return rate_limit_block(ip, uri, string.format("count=%d/%ds limit=%d", post_burst_n, post_window, post_limit))
            end
        end
    end

    -- =========================================================
    --  阶段4：高开销深度检测（开销4，仅针对高风险请求）
    -- =========================================================

    -- 【4.1】熵值评分与全局压力标记
    local entropy_score = query_entropy_score(args)
    mark_access_pressure(entropy_score)

    -- 安全路径白名单
    if is_whitelisted_path(uri, headers, args, method)
       and entropy_score < cfg.query_entropy_trigger_score then
        dlog("[WAF] 白名单放行: " .. uri)

        if cfg.enable_waf_cache_headers then
            if is_static_asset(uri) then
                ngx.header["Cache-Control"] = "public, max-age=2592000, immutable"
                ngx.header["X-Cache-Status"] = "whitelist-static"
            else
                ngx.header["Cache-Control"] = "public, max-age=300"
                ngx.header["X-Cache-Status"] = "whitelist-dynamic"
            end
        end

        ngx.ctx.wf_skip = true
        return
    end

    -- 回源保护/攻击/防御模式逻辑
    local origin_mode = (current_mode == 3) and 1 or 0
    local attack_mode = (current_mode == 2) and 1 or 0
    local defend_mode = (current_mode == 1) and 1 or 0

    if origin_mode == 1 then
        if is_wp_sensitive(uri) and (http_cookie == nil or http_cookie == "") then
            return block_request("ORIGIN_PROTECT_BLOCKED", ip, uri, "敏感路径无Cookie")
        end

        if is_html_like(uri, method, accept) then
            if args and args ~= "" and not normal_query_allowed(args) then
                return block_request("ORIGIN_PROTECT_BLOCKED", ip, uri, string.format("异常参数: %s", args), 444)
            end

            if bypass_signal or entropy_score >= cfg.query_entropy_trigger_score then
                return block_request("ORIGIN_PROTECT_BLOCKED", ip, uri, "缓存绕过信号", 444)
            end
        end

        if bypass_signal then
            return block_request("ORIGIN_PROTECT_BLOCKED", ip, uri, "缓存绕过信号", 444)
        end
    elseif attack_mode == 1 then
        if is_html_like(uri, method, accept)
           and (bypass_signal or entropy_score >= cfg.query_entropy_trigger_score) then
            return block_request("ATTACK_MODE_BLOCKED", ip, uri, "缓存绕过信号", 444)
        end
    elseif defend_mode == 1 then
        if is_html_like(uri, method, accept) then
            if bypass_signal and entropy_score >= cfg.query_entropy_trigger_score then
                return block_request("DEFEND_MODE_BLOCKED", ip, uri, "缓存绕过+高熵值", 444)
            end
        end
    end

    -- Query长度限制
    local qmax = cfg.html_query_max_len
    if origin_mode == 1 then
        qmax = cfg.origin_html_query_max_len
    elseif attack_mode == 1 then
        qmax = cfg.attack_html_query_max_len
    elseif defend_mode == 1 then
        qmax = math.floor((cfg.html_query_max_len + cfg.attack_html_query_max_len) / 2)
    end

    if is_html_like(uri, method, accept) and args and #args > qmax then
        return block_request("QUERY_TOO_LONG_BLOCKED", ip, uri, string.format("len=%d limit=%d", #args, qmax), 444)
    end

    -- 轻量级评分
    local light_score, html_like = light_score_request(uri, method, headers, args, entropy_score)

    local should_light_skip = false
    if html_like and cf_trusted and light_score < cfg.normal_light_score_threshold
       and entropy_score < cfg.query_entropy_trigger_score then
        should_light_skip = true
    end

    if should_light_skip and not bypass_signal then
        ngx.ctx.wf_skip = true
        return
    end

    -- 【4.2】纯内存快速评分（决定是否进入Redis深度检测）
    local quick_risk_score = 0

    if looks_suspicious_ua(ua) then quick_risk_score = quick_risk_score + 15 end

    if bypass_signal and not is_static_asset(uri) then quick_risk_score = quick_risk_score + 10 end

    if cfg.block_path_traversal then
        local decoded_uri = fully_decode(uri):lower()
        for _, s in ipairs(cfg.path_traversal_signals) do
            if decoded_uri:find(s, 1, true) then
                quick_risk_score = quick_risk_score + 20
                break
            end
        end
    end

    if range_hdr and not is_static_asset(uri) then quick_risk_score = quick_risk_score + 10 end

    if has_malicious_params(args, uri, method, accept) then quick_risk_score = quick_risk_score + 15 end

    if args and #args > cfg.global_query_hard_limit then quick_risk_score = quick_risk_score + 10 end

    if cfg.block_empty_cookie and (http_cookie == nil or http_cookie == "") then
        local accept_hdr = headers["accept"] or headers["Accept"] or ""
        if is_html_like(uri, method, accept_hdr) then
            quick_risk_score = quick_risk_score + 5
        end
    end

    if entropy_score > 0.8 then quick_risk_score = quick_risk_score + 10 end

    -- 【4.2】采样机制（自适应调节，保护 Redis 同时不遗漏高风险请求）
    --  优化：根据全局请求量动态调节采样率
    -- - 低负载时：按模式默认采样率（确保数据完整性）
    -- - 高负载时：自动降低低风险请求的采样率（保护 Redis 容量）
    -- - 高分请求：始终 100% 采样（不遗漏高风险）
    -- - 中分请求：高负载时适度降采样
    local should_check_redis = false

    -- 高分请求（>=30）：始终连接 Redis，不降采样
    if quick_risk_score >= 30 then
        should_check_redis = true
        log("info", "HIGH_RISK_REDIS_CHECK", ip, uri,
            string.format("quick_score=%d, connecting to Redis", quick_risk_score))
    else
        --  自适应采样率：基于全局请求量动态调节
        local mode_sampling_rates = {[0] = 0.1, [1] = 0.2, [2] = 0.5, [3] = 1.0}
        local base_rate = mode_sampling_rates[current_mode] or 0.1
        
        -- 获取全局请求量，计算负载因子（0~1）
        local req_total = tonumber(SH_META and SH_META:get("wf:g:req_total") or "0") or 0
        local flood_threshold = cfg.global_req_flood_threshold
        local load_factor = math.min(1.0, req_total / flood_threshold)
        
        -- 动态采样率：负载越高，降采样越激进（最低保留 25% 基础率）
        local scale = 1.0 - load_factor * 0.75
        local sample_rate = base_rate * math.max(0.25, scale)
        
        -- 中分请求（15-29）：高负载时仍保持较高采样率
        if quick_risk_score >= 15 then
            sample_rate = math.max(sample_rate, 0.3)  -- 中分请求最低 30%
        end

        if math.random() < sample_rate then
            should_check_redis = true
            log("info", "LOW_RISK_SAMPLED", ip, uri,
                string.format("score=%d sampled (mode=%d rate=%.0f%% load=%.0f%%)",
                    quick_risk_score, current_mode, sample_rate * 100, load_factor * 100))
        end
    end

    if not should_check_redis then
        dlog(string.format("低风险请求跳过Redis: score=%d ip=%s uri=%s", quick_risk_score, ip, uri))
        return
    end

    -- 【4.3】Redis分布式评分与集群攻击检测
    local red = redis_connect()
    if not red then
        -- =========================================================
        --  Redis 不可用时的本地风控模式
        -- 不"完全放行"，而是基于 quick_risk_score + 本地信号做保守拦截
        -- =========================================================
        if get_local_ban_cache(ip) then
            return block_request("LOCAL_BAN_CACHE_HIT", ip, uri)
        end
        if quick_risk_score >= 35 then
            return block_request("LOCAL_DEFENSE_HIGH_SCORE", ip, uri,
                string.format("quick_score=%d redis_down", quick_risk_score))
        end
        local redis_down_since = tonumber(SH_META and SH_META:get("redis:circuit_breaker:last_open") or "0")
        if redis_down_since and redis_down_since > 0 then
            local down_duration = ngx.now() - redis_down_since
            local strict_threshold = 20  -- Redis 中断超过 30s 后的拦截阈值
            if down_duration > 30 and quick_risk_score >= strict_threshold then
                return block_request("LOCAL_DEFENSE_EXTENDED_OUTAGE", ip, uri,
                    string.format("quick_score=%d down=%ds threshold=%d",
                        quick_risk_score, down_duration, strict_threshold))
            end
        end
        
        log("warn", "REDIS_DOWN_DEGRADE", ip, uri,
            string.format("Redis不可用，降级为本地风控 quick_score=%d", quick_risk_score))
        return
    end

    local banned, source = is_banned(red, ip)
    if banned then
        ngx.ctx.redis_conn = red
        return block_request("IP_ALREADY_BANNED", ip, uri, string.format("source=%s", source))
    end

    local flags = classify_request(uri, method, headers, args, entropy_score, attack_mode, origin_mode)
    local is_cluster, uri_c, ip_c = detect_cluster(red, ip, uri)
    flags.is_cluster = is_cluster
    flags.cluster_uri_count = uri_c
    flags.cluster_ip_count = ip_c

    local res = evaluate_access(red, ip, uri, method, flags)
    if not res then
        redis_close(red)
        return
    end

    local banned_flag = tonumber(res[1]) or 0
    local current_risk = tonumber(res[2]) or 0
    local current_rep = tonumber(res[3]) or 100
    local burst_n = tonumber(res[4]) or 0
    local slow_n = tonumber(res[5]) or 0
    local uniq_n = tonumber(res[6]) or 0

    ngx.ctx.wf_ip = ip
    ngx.ctx.wf_uri = uri
    ngx.ctx.wf_score = current_risk
    ngx.ctx.wf_rep = current_rep
    ngx.ctx.wf_burst = burst_n
    ngx.ctx.wf_slow = slow_n
    ngx.ctx.wf_uniq = uniq_n
    ngx.ctx.wf_skip = false

    -- 【4.4】最终决策与响应
    if banned_flag == 1 then
        local ban_ttl = tonumber(res[7]) or cfg.ban_soft
        local ban_reason = res[8] or "unknown"
        set_local_ban_cache(ip, cfg.local_ban_cache_ttl)
        redis_close(red)
        return block_request("IP_BANNED_ACCESS", ip, uri,
            string.format("score=%d rep=%d reason=%s ttl=%d", current_risk, current_rep, ban_reason, ban_ttl))
    end

    if current_risk >= 45 then
        ngx.header["Retry-After"] = "10"
        ngx.header["X-WF-Score"] = tostring(current_risk)
        ngx.header["X-WF-Rep"] = tostring(current_rep)
        dlog(string.format("高风险请求: ip=%s score=%d rep=%d", ip, current_risk, current_rep))
    end

    -- 末尾统一设置动态内容缓存头
    if cfg.enable_waf_cache_headers and not is_static_asset(uri) and not is_wp_sensitive(uri) and not is_wp_api(uri) then
        local bypass_key = "wf:bypass:" .. ip
        local bypass_count = tonumber(SH_META and SH_META:get(bypass_key) or "0") or 0

        if bypass_count >= 9 and bypass_count < 16 then
            ngx.header["Cache-Control"] = "public, max-age=30, no-cache"
            ngx.header["Retry-After"] = "30"
            ngx.header["X-WAF-Bypass-Stage"] = "2-warning"
            ngx.header["X-WAF-Bypass-Count"] = tostring(bypass_count)
            dlog(string.format("回源阶段2: 短缓存+警告 count=%d", bypass_count))
        elseif bypass_count >= 4 and bypass_count < 9 then
            ngx.header["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
            ngx.header["X-WAF-Bypass-Stage"] = "1-cache-forced"
            ngx.header["X-WAF-Bypass-Count"] = tostring(bypass_count)
            dlog(string.format("回源阶段1: 强制缓存 count=%d", bypass_count))
        else
            ngx.header["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
            ngx.header["X-WAF-Cache"] = "dynamic-short-cache"
        end
    end

    redis_close(red)
end

-- =========================================================
-- Log阶段缓存反馈处理
-- =========================================================
function _M.log()
    if ngx.ctx.wf_skip then
        return
    end

    local ip = ngx.ctx.wf_ip
    if not ip or ip == "" then
        local headers_log = ngx.req.get_headers(50)
        local raw_ip = headers_log["cf-connecting-ip"] or ngx.var.remote_addr
        ip = ip_to_number(raw_ip) and raw_ip or "0.0.0.0"
    end

    local uri = ngx.ctx.wf_uri or ngx.var.uri or "/"
    local status = ngx.var.upstream_cache_status or ""

    if is_logged_user() then
        return
    end

    if uri == "/wp-login.php"
        or uri == "/wp-cron.php"
        or uri == "/wp-sitemap.xml"
        or uri == "/wp-admin/admin-ajax.php" then
        return
    end

    local cache_status = tolower(status)
    if cache_status == "hit" then
        return
    end

    local is_miss = (cache_status == "miss" or cache_status == "expired"
        or cache_status == "stale" or cache_status == "updating")
    local is_bypass = (cache_status == "bypass" or cache_status == "revalidated")

    if not is_miss and not is_bypass then
        return
    end

    --  提前捕获 UA：timer 回调中 request context 可能已清理，
    --    优先从 ngx.ctx.wf_ua 读取（access 阶段存入），避免 ngx.req.get_headers() 返回空
    local ua_for_timer = ngx.ctx.wf_ua or ""
    if ua_for_timer == "" then
        -- 降级：ctx 不可用时尝试 get_headers
        local ok_h, headers_pre = pcall(ngx.req.get_headers, 50)
        if ok_h and headers_pre then
            ua_for_timer = headers_pre["user-agent"] or ""
        end
    end

    local ok, err = ngx.timer.at(0, function(premature, ip, uri, is_miss, is_bypass, status, req_id, ua_timer)
        if premature then
            return
        end

        local red = redis_connect()
        if not red then
            return
        end

        local res = evaluate_feedback(red, ip, uri, is_miss, is_bypass)
        if not res then
            redis_close(red)
            return
        end

        local banned_flag = tonumber(res[1]) or 0
        local current_risk = tonumber(res[2]) or 0

        mark_feedback_pressure(is_miss, is_bypass)

        --  智能回源封禁：渐进式策略 + bot伪装检测
        local miss_n = tonumber(res[4]) or 0
        local bypass_n = tonumber(res[5]) or 0

        -- 检查是否是伪装的探测bot（UA 由 log() 阶段提前捕获传入，避免 timer 中 request context 已失效）
        local ua = ua_timer or ""
        local is_suspicious_bot = false

        -- 可疑bot特征：UA声称是bot但行为异常
        if ua:lower():find("bot") or ua:lower():find("spider") or ua:lower():find("crawler") then
            -- 真正的搜索引擎bot不会频繁nocache
            if bypass_n > 5 or miss_n > 5 then
                is_suspicious_bot = true
                log("warn", "SUSPICIOUS_BOT_DETECTED", ip, uri,
                    string.format("ua=%s bypass=%d miss=%d", ua, bypass_n, miss_n))
            end
        end

        -- 封逻条件（满足任一即封）：
        local should_ban = false
        local ban_reason = "unknown"
        local ban_ttl = nil  -- should_ban 分支设置，banned_flag 分支优先使用

        if miss_n > cfg.miss_window_limit * 2 or bypass_n > cfg.bypass_window_limit * 2 then
            should_ban = true
            ban_reason = "excessive_origin"
        elseif is_suspicious_bot and (bypass_n > 5 or miss_n > 5) then
            should_ban = true
            ban_reason = "suspicious_bot"
        elseif miss_n > 10 and bypass_n > 10 then
            -- 两者都很高，明显是攻击
            should_ban = true
            ban_reason = "combined_attack"
        end

        if should_ban then
            local ban_key = "wf:ban:" .. ip
            ban_ttl = cfg.ban_mid  -- 封禁1小时
            red:set(ban_key, ban_reason, "EX", ban_ttl)
            set_local_ban_cache(ip, cfg.local_ban_cache_ttl)
            log("warn", "ORIGIN_ABUSE_BANNED", ip, uri,
                string.format("miss=%d bypass=%d reason=%s ttl=%d ua=%s",
                    miss_n, bypass_n, ban_reason, ban_ttl, ua))
            banned_flag = 1
        end

        if banned_flag == 1 then
            --  优先使用 should_ban 分支已设置的 ban_ttl/ban_reason，FEEDBACK_SCRIPT 返回值作为备选
            --    避免 should_ban 设置的正确值被 FEEDBACK_SCRIPT 返回的 0/"" 覆盖
            local log_ban_ttl = ban_ttl or tonumber(res[6]) or cfg.ban_soft
            local log_ban_reason = ban_reason or res[7] or "cache"
            set_local_ban_cache(ip, cfg.local_ban_cache_ttl)
            log("warn", "IP_BANNED_FEEDBACK", ip, uri,
                string.format("score=%d reason=%s cache_status=%s",
                    current_risk, log_ban_reason, status))
        end

        redis_close(red)
    end, ip, uri, is_miss, is_bypass, status, ngx.ctx.wf_req_id, ua_for_timer)

    if not ok then
        ngx.log(ngx.ERR, string.format("[WAF] Failed to create timer: %s", err or "unknown"))
    end
end

-- =========================================================
-- 手工控制接口
-- =========================================================
function _M.add_whitelist_path(path)
    if not path or path == "" then
        return nil, "empty path"
    end

    local red, err = redis_connect()
    if not red then
        return nil, err
    end

    local ok, e2 = red:sadd("wf:wl:path", path)
    redis_close(red)
    pcall(merge_whitelist_from_redis)
    log("info", "WHITELIST_ADDED", nil, nil, path)
    return ok, e2
end

function _M.remove_whitelist_path(path)
    if not path or path == "" then
        return nil, "empty path"
    end

    local red, err = redis_connect()
    if not red then
        return nil, err
    end

    local ok, e2 = red:srem("wf:wl:path", path)
    redis_close(red)
    pcall(merge_whitelist_from_redis)
    log("info", "WHITELIST_REMOVED", nil, nil, path)
    return ok, e2
end

function _M.enable_attack_mode(ttl)
    set_mode(2, ttl or cfg.attack_mode_ttl, "manual attack")
    return true
end

function _M.enable_origin_protect(ttl)
    set_mode(3, ttl or cfg.origin_protect_ttl, "manual origin protect")
    return true
end

function _M.clear_global_modes()
    clear_mode()
    return true
end

function _M.get_status()
    return {
        mode = get_mode(),
        whitelist_exact = wl_exact,
        whitelist_prefix = wl_prefix,
        last_whitelist_reload = wl_last_reload,
    }
end

-- =========================================================
-- 自动执行对应阶段（兼容 init_worker_by_lua_file 加载方式）
-- =========================================================
-- =========================================================

--  显式开关：只有脚本直跑时才启用自动分发
local AUTO_DISPATCH = (MODULE_NAME == nil)  -- require() 模块模式下不自动执行

if AUTO_DISPATCH then
    local phase = ngx.get_phase()
    if phase == "init_worker" then
        -- Worker 初始化阶段
        _M.init_worker()
        return
        
    elseif phase == "access" then
        -- 请求访问阶段（回源安全防护核心）
        -- 第一层防护：检测可疑UA、缓存绕过、频率限制等
        _M.access()
        return
        
    elseif phase == "log" then
        -- 日志记录阶段（回源反馈分析）
        -- 统计缓存命中率，评估回源压力，智能封禁
        _M.log()
        return
    end
end

-- =========================================================
-- 模块导出
-- =========================================================
-- - 恶意参数规则 (cfg.malicious_params) 在脚本中硬编码
-- - 修改配置后，请重启 Nginx: nginx -s reload
-- - 白名单从文件自动加载，每 5 分钟刷新一次
-- - 防御模式通过 Redis 控制，无需重启

-- 其他阶段（rewrite、header_filter、body_filter 等）不执行
-- 返回空模块对象供 require 方式使用
return _M
