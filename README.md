# OpenResty Cloudflare WordPress WAF

[![OpenResty](https://img.shields.io/badge/OpenResty-%E2%89%A5%201.21.4-blue?logo=openresty)](https://openresty.org/)
[![Redis](https://img.shields.io/badge/Redis-%E2%89%A5%207.0-red?logo=redis)](https://redis.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

一款专为运行在 OpenResty + Cloudflare CDN 上的 WordPress 站点设计的高性能多层 Web 应用防火墙。具备自适应防御机制、Redis 驱动的风险评分、智能速率限制和自动全局模式切换功能。

> **Note**: This project's code and configuration comments are primarily in Chinese. This document is written entirely in Chinese; for the English version, please see [README_en.md](README_en.md)。
---
> ⚠️ **重要安全声明:**
> 
> 本脚本目前仅为作者个人使用与维护，**未经过大规模生产环境验证、第三方安全审计及全面攻防测试**，安全性、稳定性与兼容性尚未达到100%严谨标准。
> 若需部署到生产环境，请务必**自行充分测试、评估风险后谨慎使用**，因直接使用造成的任何问题，作者不承担相关责任。

## 目录

- [快速开始](#快速开始)
- [架构概览](#架构概览)
- [脚本工作原理](#脚本工作原理)
- [核心特性](#核心特性)
- [前置要求](#前置要求)
- [配置说明](#配置说明)
- [IP 白名单](#ip-白名单)
- [监控与日志](#监控与日志)
- [测试与验证指南](#测试与验证指南)
- [故障排查](#故障排查)
- [版本兼容性](#版本兼容性)
- [性能调优](#性能调优)
- [术语表](#术语表)
- [常见问题](#常见问题)
- [安全设计说明](#安全设计说明)
- [贡献指南](#贡献指南)
- [许可证](#许可证)
- [免责声明](#免责声明)

---

## 快速开始

### 1. 环境准备

```bash
# 安装依赖（Debian/Ubuntu 示例）
apt update && apt install -y openresty redis-server

# 验证安装
openresty -v
redis-cli --version
```

### 2. 部署 WAF

```bash
# 下载脚本
wget https://raw.githubusercontent.com/Asunano/OpenResty-Cloudflare-WordPress-WAF/main/openresty-cloudflare-wp-waf.lua -P /www/server/nginx/lua/

# 创建白名单文件
touch /www/server/nginx/lua/waf_whitelist.txt
```

### 3. 配置 Nginx

编辑你的站点配置文件，添加以下内容：

```nginx
# 在 http 块中添加（全局配置）
lua_shared_dict wf_ban_cache  16m;
lua_shared_dict wf_meta_cache 16m;
init_worker_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;

# 在 server 块中添加（站点级配置）
server {
    listen 80;
    server_name your-domain.com;

    # WAF 核心配置
    access_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;
    log_by_lua_file /www/server/nginx/lua/openresty-cloudflare-wp-waf.lua;

    # 你的原有配置
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. 重启服务

```bash
nginx -t && nginx -s reload
systemctl restart redis-server
```

### 5. 验证生效

```bash
# 测试 SQL 注入拦截
curl "http://your-domain.com/?id=1' union select 1,2,3--"
# 应返回 403 Forbidden
```
### 6.配置修改

WAF 配置参考指南 [CONFIG_zh.md](CONFIG_zh.md)

---

## 架构概览

```
                   客户端 / 攻击者
                         │
                   Cloudflare CDN
            (cf-ray, cf-connecting-ip, etc.)
                         │
               OpenResty (Nginx + Lua)
  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐
  │ init_worker  │  │    access    │  │     log       │
  │ - 加载规则   │  │  - 阶段1-4检测│  │ - 缓存反馈    │
  │ - 初始化Redis│  │  - 风险评分   │  │ - 智能封禁    │
  └─────────────┘  └──────┬───────┘  └───────┬───────┘
                          │                   │
                 ┌────────▼───────────────────▼──┐
                 │   lua_shared_dict (内存缓存)   │
                 │   wf_ban_cache / wf_meta_cache │
                 └────────┬───────────────────────┘
                          │
                    Redis (风险评分引擎)
  - 风险/信誉评分          - 突发/慢速限制
  - 集群攻击检测           - 每日统计数据
  - 分布式锁机制           - 路径白名单
```

---

## 脚本工作原理

### 执行模型：三阶段生命周期

WAF 脚本在两个不同的执行模式间自动切换，通过 Nginx 的三个处理阶段覆盖请求全生命周期：

```
┌──────────────────────────────────────────────────────┐
│              单次脚本加载（模块模式）                   │
│  require("openresty-cloudflare-wp-waf") → 返回 _M     │
│  仅加载一次，代码缓存后各阶段手动调用 _M.xxx()          │
├──────────────────────────────────────────────────────┤
│              多阶段脚本加载（文件模式）                  │
│  Nginx 每个阶段重新读取脚本 → 根据 ngx.get_phase()     │
│  自动分发到对应函数                                     │
└──────────────────────────────────────────────────────┘
```

| Nginx 阶段 | 对应函数 | 触发时机 | 主要工作 |
|-----------|----------|---------|---------|
| `init_worker` | `_M.init_worker()` | 每个 Worker 进程启动时执行一次 | 预编译所有正则、从文件加载 IP 白名单、验证共享内存状态 |
| `access` | `_M.access()` | **每个 HTTP 请求**到达时 | 核心 WAF 逻辑：4 阶段递进检测、风险评分、拦截决策 |
| `log` | `_M.log()` | 请求处理完毕后 | 通过 `ngx.timer.at` 异步分析缓存回源行为、反馈评分、智能封禁 |

### Access 阶段：渐进式四层检测

`access` 阶段是 WAF 的核心，按开销从小到大递进检测，确保 90%+ 的正常请求在前两层就快速放行：

**阶段 1 — 基础豁免与快速通道**（开销极低，纯内存操作）

采用"白名单优先"策略，按以下优先级依次判断：

1. **HTTP 方法白名单**：仅允许 `GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS`，其余直接返回 405
2. **IP 白名单豁免**：匹配本地文件（支持 CIDR 网段）或 Redis 动态白名单的 IP，直接放行并记录日志
3. **系统路径豁免**：`wp-cron.php`（localhost/内网放行、外部 IP 限制 1次/10s）、健康检查、robots.txt 等核心路径
4. **已登录用户分层保护**：不再完全豁免，而是执行精简版基线检查（仅检测 RCE、路径穿越、极端 UA、超长查询），Cookie 需符合 WordPress 签名格式 `user|expiry|token|hmac`
5. **Fast Path 快速放行**：静态资源（css/js/图片/字体）→ 设置 30 天强缓存；核心页面 → 设置 1 小时缓存；均添加 `X-Cache-Status` 头

> 约 90% 的正常流量在此阶段结束，无需进入后续检测。

**阶段 2 — 纯内存硬拦截**（开销 1-2 次共享内存操作，无 Redis IO）

对明确的攻击模式直接在 openresty 层面拦截，不依赖外部服务：

| 检测项 | 方法 | 优化 |
|--------|------|------|
| 路径穿越 | 递归 URL 解码（最多 20 层）+ 模式匹配 | 无 `%` 编码的请求跳过重检 |
| 恶意参数 | 预编译正则（RCE/SQLi/XSS 分组） | 无 SQL 字面量的请求（约 80%）跳过 SQLi 正则；参数 < 8 字符跳过 |
| 查询超长 | `#args` 长度硬限制 | 纯字符串长度判断，O(1) |
| 可疑 UA | 子串匹配扫描器特征 | 仅日志记录，不硬拦 |
| 全局洪水 | `lua_shared_dict` 全局计数器 | 10s 窗口，超阈值自动升级到回源保护模式 |
| 本地频率限制 | 按 IP + IP:URI 双维度计数 | 10s/60s 窗口，阈值 = base × 2 |
| Range 头 | 非静态资源禁止 Range | 防止大文件 Range 耗尽资源 |
| 缓存绕过立即拦截 | 检测 nocache 参数/头 | 非静态资源含绕过信号直接 444 |

**阶段 3 — 上下文感知智能拦截**（开销 2-3，需解析请求上下文）

需要结合请求的多个特征进行联合判断，比阶段 2 更"聪明"：

- **回源绕过渐进式响应**：统计每个 IP 的绕过次数，分三阶段响应 → `4-8次` 强制缓存 → `9-15次` 警告 → `>15次` 返回 429
- **空 Cookie 多维评分**：综合 CF 信任分 + UA 浏览器特征 + URI 熵值 + 缓存状态 + 频率计数，给出 0-10+ 的可疑评分，≥7 拦截、≥4 警告
- **空 Referer 检测**：仅对 POST 请求生效，豁免 API/JSON/CORS/静态资源路径

**阶段 4 — Redis 深度检测**（开销 4+，Redis 往返 + Lua 脚本原子执行）

只有通过前三层且 `quick_score > 0`（有可疑信号）的请求才进入此阶段。核心是一个嵌入 Redis 的 Lua 脚本（`ACCESS_SCRIPT`），在 Redis 服务端原子执行以下操作：

```
┌─ 输入标志位 ──────────────────────────────────────────┐
│ risk_add    rep_penalty  rep_bonus                    │
│ has_cookie  has_referer  is_html  is_api  is_auth     │
│ is_static   is_bypass    ua_suspicious  is_entropy     │
│ is_cluster                                              │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ Redis Lua 脚本原子执行 ──────────────────────────────┐
│                                                         │
│  1. 读取当前 risk / rep 分值                             │
│  2. 记录 URI 到访问集合，统计唯一访问数                    │
│  3. 根据 rep 信誉动态计算速率限制阈值                      │
│     burst_limit = burst_base + floor((rep-50)/4)         │
│     slow_limit  = slow_base  + floor((rep-50)/6)         │
│  4. INCR 突发/慢速计数器，首次加窗口过期                   │
│  5. 自然衰减：risk = risk - floor(risk × 0.03)          │
│  6. 累加风险评分（熵值+15、集群+20、绕过标记+10...）      │
│  7. 人类/爬虫行为建模（Cookie/Referer/UA/唯一URI）        │
│  8. 根据总分 + 信誉决定封禁级别（15min/1hr/24hr）          │
│                                                         │
└───────────────────────────────────────────────────────┘
```

**人类/爬虫行为建模**：WAF 不是简单地把所有无 Cookie 请求当爬虫，而是通过多维特征做精细判断：

- **人类特征**：有 Cookie（+1）、有 Referer（+1）、HTML 页面且两者都有且唯一 URI ≤ 15（+1）
- **爬虫特征**：可疑 UA（+1）、含认证路径但无 Cookie（+2）、API 无 Cookie 且唯一 URI 过多（+1）、静态资源无 Cookie 且唯一 URI > 30（+1）、缓存绕过（+1）、POST 无 Referer（+1）

`爬虫分 ≥ 2` 时触发惩罚，信誉分降低、风险分升高。

**自适应速率阈值**：信誉分越高，速率限制越宽松（高信誉用户获得更大的请求配额），反之信誉低时限制收紧，实现"好人多放、坏人多拦"。

### Log 阶段：异步反馈与智能封禁

`log` 阶段在请求响应完成后执行，通过 `ngx.timer.at(0, callback)` 创建**零延迟异步定时器**来处理，不会阻塞用户响应：

1. 检查 `upstream_cache_status`：`HIT` 直接跳过，`MISS/BYPASS/EXPIRED/STALE` 进入处理
2. 异步执行 `FEEDBACK_SCRIPT`（Redis Lua 脚本），统计 MISS/BYPASS 次数，超标时增加风险分
3. 可疑爬虫检测：UA 声称是 bot 但频繁 nocache 的行为 → 标记 + 封禁
4. 回源滥用封禁三条件：miss 超标 ×2 / bypass 超标 ×2 / 两者同时超标
5. 封禁后同步写入本地共享内存缓存，后续请求在阶段 2 即使 Redis 不可用也能命中

### 熔断器原理

```
正常状态 ──连续失败 5 次──▶ 熔断开启（10s）
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
              后台探测定时器         本地共享内存降级
              (每 3s 探测一次)        ├─ 本地封禁缓存命中
                    │                ├─ quick_score ≥ 35 拦截
              恢复成功？              └─ 中断 > 30s → 更严格阈值
                    │
          ┌────否──┴──是──┐
          ▼               ▼
    退避升级（20s→60s）  熔断关闭，恢复正常
```

- **双阶梯超时**：connect 30ms（快速失败，避免排队）、eval 100ms（给 Redis 充足计算时间）
- **阶梯退避**：10s → 20s → 60s，避免频繁切换
- **安全降级**：本地共享内存持续提供基础防护，不会因 Redis 故障而门户大开

### 自适应采样

为避免高负载下 Redis 过载，WAF 动态调整进入阶段 4 的采样率：

| 场景 | 采样策略 |
|------|---------|
| 风险评分 ≥ 30（高风险） | 100% 始终采样 |
| 风险评分 15-29（中风险） | 高负载时最低保持 30% |
| 低风险 + 低负载 | 各模式默认采样率（正常 10% → 回源保护 100%） |
| 低风险 + 高负载 | 降至基础采样率的 25% |

### 性能关键技术

| 技术 | 说明 | 效果 |
|------|------|------|
| 预编译正则 | `init_worker` 阶段用 `ngx.re.match` 按攻击类型分组编译 | 避免每个请求重新编译 |
| 熵值查表法 | 预计算 0-255 字节的熵值查找表 | O(1) 替代 `math.log()` |
| 短路优化 | SQL 字面量预扫描 → 无匹配跳过 SQLi 正则 | 约 80% 流量跳过最昂贵的正 |
| 参数长度门控 | 短于 8 字符的参数跳过正则检测 | 正常短参数零开销 |
| 请求级缓存 | `ngx.ctx` 缓存 bypass/恶意参数检测结果 | 同一请求内免重复计算 |
| Pass 2 跳过 | 无 `%` 编码的请求跳过 URL 解码重检 | 正常请求零额外开销 |
| 统一头信息表 | 所有 header 键转为小写 | 避免大小写不匹配导致的漏检 |

---

## 核心特性

### 1. 四层防护体系（渐进式检测）

每个请求最多经过 4 个阶段的检测，开销随风险等级递增：

| 阶段 | 名称 | 开销 | 描述 |
|------|------|------|------|
| 1 | **基础豁免与快速通道** | 0-1 | 白名单IP、核心路径、已登录用户、静态资源。约90%的请求在此结束。 |
| 2 | **内存级硬拦截** | 1-2 | 路径穿越、恶意参数、UA检测、全局洪水检测、速率限制 |
| 3 | **上下文感知智能拦截** | 2-3 | 空Cookie分析、空Referer、XMLRPC、POST请求体、文件上传检测 |
| 4 | **Redis深度检测** | 4+ | 熵值评分、基于Redis的风险/信誉评分、集群攻击检测 |

### 2. Cloudflare 深度集成

- 验证 Cloudflare 头信息（`cf-ray`、`cf-connecting-ip`、`cf-ipcountry`、`cf-visitor`）进行信任评分
- 检测缓存绕过信号（nocache参数、Cache-Control头、X-\*绕过头）
- 区分正常缓存未命中（首次访问）和恶意绕过行为
- 渐进式绕过响应：强制缓存 → 短缓存+警告 → 拦截
- WAF 统一管理 Cache-Control 头

### 3. WordPress 专属优化安全

| 功能 | 描述 |
|------|------|
| 已登录用户基线检查 | 替代完全豁免，仅保留关键检查（RCE、路径穿越、UA长度、查询长度）。Cookie 值需 WordPress 签名格式（`user\|expiry\|token\|hmac`）才能通过。 |
| WP管理后台资产速率限制 | 防止管理员账号被滥用（load-scripts/load-styles/admin-ajax），已登录用户限制 40次/10s |
| wp-cron.php 保护 | localhost/内网免检，外部IP限制为 1次/10s |
| XMLRPC 拦截 | 缓解通过 xmlrpc.php 的暴力破解和 DDoS 攻击 |
| wp-json/wp-sitemap 白名单 | 使用原始请求 URI（重写前）匹配，正确处理 WP REST API 和站点地图 |
| POST 请求体保护 | 大小限制（1MB）、Content-Type验证、恶意文件上传检测 |
| 归档路径保护 | 仅允许GET/HEAD方法，验证查询参数 |

### 4. Redis 驱动的风险评分系统

两个 Redis Lua 脚本原子性处理所有评分操作：

**访问脚本** — 评估所有进入深度检测阶段的请求：
- **风险评分** (0-∞)：基于可疑行为累积
- **信誉评分** (0-100)：初始100，不良行为降低，良好行为恢复
- **自适应阈值**：突发/慢速限制根据信誉动态调整
- **三级封禁**：15分钟 / 1小时 / 24小时，根据严重程度分级

**反馈脚本** — 在日志阶段通过 `ngx.timer` 异步处理缓存反馈：
- 检测过度回源请求（miss/bypass滥用）
- 识别可疑爬虫（声称是bot但频繁nocache的行为）
- 对回源滥用进行渐进式封禁

### 5. 自动全局模式切换

WAF 根据全局压力信号自动在 4 种防护模式间升降级：

| 模式 | 级别 | 响应策略 | 触发条件 |
|------|------|---------|---------|
| 正常 | 0 | 标准检测 | 低于所有阈值 |
| 防御 | 1 | 更严格的HTML查询限制 | 未命中/绕过/熵值升高 |
| 攻击 | 2 | 拦截绕过+高熵值请求 | 攻击阈值被触发 |
| 回源保护 | 3 | 最严格模式（参数验证、无Cookie拦截） | 回源阈值被触发 |

压力信号在 `lua_shared_dict` 中跟踪，支持可配置的TTL窗口。降级使用滞后阈值防止模式频繁切换。

### 6. Redis 熔断器

- **阶梯式退避**：连续失败时 10s → 20s → 60s
- **后台探测定时器**：自动测试Redis连接并自我修复
- **安全本地降级**：Redis不可用时通过共享内存继续提供基础防护：
  - 本地封禁缓存命中 → 直接拦截
  - 高风险请求（quick_score ≥ 35） → 本地拦截
  - 长时间中断（>30s） → 更严格的本地阈值
- **双阶梯超时**：connect 30ms 快速失败（避免排队），eval 100ms 给 Redis 充足计算时间

### 7. 自适应采样

为了在高负载下保护Redis，WAF动态调整采样率：
- **低负载**：各模式默认采样率（正常10% → 回源保护100%）
- **高负载**：低风险请求降至基础率的25%
- **高风险（评分≥30）**：始终100%采样
- **中风险（15-29）**：即使高负载也保持最低30%采样率

### 8. 分布式锁机制

所有关键操作使用带时钟漂移保护的分布式锁：
- 白名单文件刷新
- Redis数据清理（24小时间隔）
- 熔断器重置
- 从Redis重新加载路径白名单

锁包含Worker PID和时间戳，用于安全释放验证。值匹配才删除，防止跨Worker竞态条件。

### 9. 全面检测能力

| 类别 | 检测方法 |
|------|---------|
| RCE/代码注入 | 按攻击类型分组的一次性编译正则 |
| SQL注入 | 先进行SQL字面量预扫描，再执行正则匹配 |
| XSS | 上下文感知（仅对HTML端点生效） |
| 路径穿越 | 递归URL解码 + 模式匹配 |
| 可疑UA | 带长度/上下文感知的关键字匹配 |
| 缓存绕过 | 查询参数、头信息、熵值、参数计数 |
| 熵值攻击 | 使用预计算查找表的O(1)查表检测高熵值查询 |
| 集群攻击 | Redis ZSET IP↔URI映射 + Lua脚本 |
| DDoS洪水 | 全局共享内存计数器 + 模式升级 |

### 10. 极致性能优化

- **预编译正则**：Worker初始化时编译一次，按攻击类型分组
- **熵值查找表**：O(1)查表替代 `math.log()` 调用
- **短路优化**：无SQL字面量的请求跳过SQLi正则（约80%流量）
- **参数长度门控**：短于8字符的参数跳过正则检测
- **请求级缓存**：同一请求内 `ngx.ctx` 缓存绕过/恶意参数检测结果
- **Pass 2 跳过**：无 `%` 编码的请求跳过URL解码重检
- **统一头信息表**：所有键转为小写，避免大小写不匹配问题

---

## 前置要求

### 必需组件

| 组件 | 推荐版本 | 用途 |
|------|---------|------|
| OpenResty | ≥ 1.21.4 | 基于 LuaJIT 的 Nginx，正则 JIT 完全生效 |
| Redis | ≥ 7.0 | 分布式风险评分、Lua 原子脚本、锁、白名单 |
| Cloudflare | 任意套餐 | CDN、缓存、可信头信息 |

### 必需的 Nginx 配置

```nginx
lua_shared_dict wf_ban_cache  16m;
lua_shared_dict wf_meta_cache 16m;

# Worker初始化
init_worker_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

# 访问阶段
server {
    # ... 你的站点配置 ...

    access_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

    # 日志阶段（用于缓存反馈）
    log_by_lua_file /path/to/openresty-cloudflare-wp-waf.lua;

    # 你的代理/其他配置
    location / {
        proxy_pass http://your_upstream;
    }
}
```

### Lua 模块导入方式（可选）

```lua
local waf = require("openresty-cloudflare-wp-waf")

-- 在 init_worker_by_lua 中:
waf.init_worker()

-- 在 access_by_lua 中:
waf.access()

-- 在 log_by_lua 中:
waf.log()
```

---

## 配置说明

所有配置集中在 `cfg` 表中并清晰标注：

```lua
local cfg = {
    -- ── Redis 配置 ──────────────────────────────────────────
    redis_host = "127.0.0.1",
    redis_port = 6379,
    redis_pass = nil,

    -- ── 阈值配置 ─────────────────────────────────────────────
    risk_ban_threshold = 100,     -- 风险评分达到此值封禁
    rep_ban_threshold  = 20,      -- 信誉评分低于此值封禁
    base_burst_10s     = 18,      -- 突发限制（10秒窗口）
    base_slow_60s      = 12,      -- 慢速限制（60秒窗口）

    -- ── 封禁时长 ────────────────────────────────────────────
    ban_soft = 900,    -- 15分钟
    ban_mid  = 3600,   -- 1小时
    ban_hard = 86400,  -- 24小时

    -- ── 功能开关 ────────────────────────────────────────────
    block_xmlrpc            = true,
    block_malicious_params  = true,
    block_path_traversal    = true,
    enable_local_rate_limit = true,
    -- ... 更多配置 ...
}
```

### 自定义恶意参数规则

编辑 `malicious_rce`、`malicious_sqli` 和 `malicious_xss` 表添加或删除模式：

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

### 自定义恶意 UA 检测

编辑 `malicious_uas` 表。注意：某些常见被拦截的 UA（如 `go-http-client` 和 `headlesschrome`）已被有意排除，以避免误拦截合法服务。

---

## IP 白名单

### 文件式白名单

在 `cfg.local_allow_file` 指定的路径（默认：`/www/server/nginx/lua/waf_whitelist.txt`）创建文件：

```
# 单个IP
192.168.1.100
10.0.0.50

# CIDR网段（需要bit库支持完整功能）
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12

# 127.0.0.1 默认始终包含在白名单中
```

白名单每 `cfg.whitelist_refresh_interval` 秒自动重新加载，且只有一个Worker执行文件IO（通过分布式锁保证）。

### Redis 动态白名单

通过 Redis 集合添加白名单路径：

```bash
redis-cli SADD "wf:wl:path" "/custom-whitelist-path"
redis-cli SADD "wf:wl:path" "/custom-prefix/*"
```

以 `*` 结尾的路径视为前缀匹配；其他路径为精确匹配。WAF默认包含WordPress核心文件的白名单路径（`/wp-content/`、`/wp-includes/`、`/wp-json/`、`.well-known/` 等）。

### 编程式 API

```lua
-- 添加/删除白名单路径
waf.add_whitelist_path("/api/public")
waf.remove_whitelist_path("/api/public")

-- 手动控制模式
waf.enable_attack_mode(90)       -- 开启攻击模式90秒
waf.enable_origin_protect(60)    -- 开启回源保护60秒
waf.clear_global_modes()         -- 恢复正常模式

-- 获取状态
local status = waf.get_status()
-- 返回: { mode, whitelist_exact, whitelist_prefix, last_whitelist_reload }
```

### 运行状态端点

WAF 内置了 HTTP 状态查看端点，返回纯文本格式的运行指标：

```lua
-- 在 cfg 中启用：
status_endpoint_enabled = true,           -- 开启状态端点
status_endpoint_path = "/waf-status",     -- 访问路径
status_endpoint_allowed_ips = {           -- 仅允许的 IP
    "127.0.0.1",
},
status_metrics_ttl_days = 7,              -- 独立指标存储天数（Redis），0=永久
```

```bash
curl http://127.0.0.1/waf-status
# 当前模式: 正常(0)
# 自动模式: 开启
# 全局Miss计数: 12
# 全局Bypass计数: 3
# 本地封禁IP数: 2
# 封禁IP列表: 1.2.3.4(剩余900秒) 5.6.7.8(剩余3600秒)
# Redis状态: 已连接
# Redis统计(7天窗口): 总请求=54000, 拦截=320, 放行=53680
# Worker PID: 12345
```

> **独立指标存储**：开启状态端点后，WAF 在 Redis 中维护独立的 `wf:status:*` 键空间用于长期统计，不受短周期 `global_counter_ttl` 影响。`status_metrics_ttl_days` 控制数据保留时间（天）。
>
> **安全提示**：默认 `false`（关闭），非白名单 IP 访问返回 404。生产环境建议仅对内网监控系统开放。

---

## 监控与日志

### 日志格式

所有日志包含请求ID用于关联追踪：

```
[WAF] [警告] [通用频率限制] (RATE_LIMITED) req_id=... ip=xxx uri=/path details...
[WAF] [错误] [本地封禁缓存命中] (LOCAL_BAN_CACHE_HIT) req_id=... ip=xxx uri=/path score=120...
```

### 拦截事件（当 `force_block_log_error=true` 时以ERROR级别记录）

| 事件 | 含义 | HTTP状态码 |
|------|------|-----------|
| `MALICIOUS_PARAM_BLOCKED` | 检测到恶意参数 | 403 |
| `PATH_TRAVERSAL_BLOCKED` | 路径穿越攻击 | 403 |
| `EMPTY_COOKIE_BLOCKED` | HTML请求无Cookie | 403 |
| `EMPTY_REFERER_BLOCKED` | POST请求无Referer | 403 |
| `RATE_LIMITED` | 超过速率限制 | 429 |
| `LOCAL_RATE_LIMIT_BLOCKED` | 本地频率限制拦截 | 429 |
| `XMLRPC_BLOCKED` | XMLRPC请求被拦截 | 403 |
| `BYPASS_IMMEDIATE_BLOCKED` | 缓存绕过立即拦截 | 444 |
| `BYPASS_LIMIT_TRIGGERED` | 回源绕过限制触发 | 429 |
| `LOCAL_BAN_CACHE_HIT` | 本地封禁缓存命中 | 403 |
| `ORIGIN_PROTECT_BLOCKED` | 回源保护模式拦截 | 444 |
| `POST_BODY_TOO_LARGE` | POST请求体超过1MB | 413 |
| `INVALID_CONTENT_TYPE` | 非法Content-Type | 415 |
| `MALICIOUS_FILE_UPLOAD` | 恶意文件上传拦截 | 403 |
| `CIRCUIT_BREAKER_BLOCKED` | 熔断器拦截 | 503 |
| `ATTACK_MODE_BLOCKED` | 攻击模式拦截 | 444 |
| `DEFEND_MODE_BLOCKED` | 防御模式拦截 | 403 |
| `WP_CRON_RATE_LIMITED` | WP-Cron频率限制 | 429 |
| `LOGGED_USER_WP_ASSET_RATE_LIMITED` | 已登录用户WP资产频率限制 | 429 |
| `ORIGIN_ABUSE_BANNED` | 回源滥用封禁 | 403 |
| `RANGE_HEADER_BLOCKED` | Range头拦截 | 403 |
| `ARCHIVES_METHOD_BLOCKED` | 归档方法拦截 | 405 |
| `ARCHIVES_ARGS_BLOCKED` | 归档参数拦截 | 403 |
| `QUERY_TOO_LONG_BLOCKED` | 查询字符串过长拦截 | 403 |
| `INVALID_METHOD` | 非法HTTP方法 | 405 |
| `MALICIOUS_POST_BODY` | 恶意POST请求体拦截 | 403 |
| `LOCAL_DEFENSE_HIGH_SCORE` | 本地防御-高分拦截（Redis不可用时） | 403 |
| `LOCAL_DEFENSE_EXTENDED_OUTAGE` | 本地防御-长断拦截（Redis长时间中断） | 403 |
| `IP_ALREADY_BANNED` | IP已被封禁（重复访问） | 403 |
| `IP_BANNED_ACCESS` | IP在access阶段被封禁 | 403 |
| `IP_BANNED_FEEDBACK` | IP在log反馈阶段被封禁 | 403 |
| `WHITELIST_BYPASS_BLOCKED` | 白名单IP异常绕过拦截 | 444 |

### 共享内存监控

WAF自动监控 `lua_shared_dict` 使用率，在80%容量时记录警告，95%时记录严重告警：

```
[WAF] [SHM_HIGH] wf_ban_cache usage=85.3% capacity=16777216 free=2460128 bytes — 建议增大 lua_shared_dict 容量
```

---

## 测试与验证指南

### 1. 基础功能测试

```bash
# 测试正常请求
curl -I http://your-domain.com/
# 应返回 200 OK

# 测试SQL注入拦截
curl -I "http://your-domain.com/?id=1' OR 1=1--"
# 应返回 403 Forbidden

# 测试XSS拦截
curl -I "http://your-domain.com/?q=<script>alert(1)</script>"
# 应返回 403 Forbidden

# 测试路径穿越拦截
curl -I "http://your-domain.com/../../etc/passwd"
# 应返回 403 Forbidden
```

### 2. 速率限制测试

```bash
# 发送20个快速请求
for i in {1..20}; do curl -I http://your-domain.com/; done
# 第19-20个请求应返回 429 Too Many Requests
```

### 3. 白名单测试

```bash
# 添加IP到白名单
echo "192.168.1.100" >> /www/server/nginx/lua/waf_whitelist.txt
# 等待刷新或重启Nginx

# 从白名单IP发送恶意请求
curl -I "http://your-domain.com/?id=1' OR 1=1--"
# 应返回 200 OK（白名单豁免）
```

### 4. Redis 评分测试

```bash
# 连续发送多个恶意请求
for i in {1..10}; do curl -I "http://your-domain.com/?id=1' OR 1=1--"; done

# 查看Redis中的风险评分
redis-cli GET "wf:risk:你的IP"
# 应返回大于0的数值
```

---

## 故障排查

### 1. WAF 不生效

- 检查Nginx配置语法：`nginx -t`
- 确认 `access_by_lua_file` 和 `log_by_lua_file` 路径正确
- 查看Nginx错误日志：`tail -f /www/server/nginx/logs/error.log`
- 确认 `lua_code_cache on;`（默认开启）

### 2. Redis 连接失败

- 检查Redis服务状态：`systemctl status redis-server`
- 验证Redis端口和密码配置
- 查看WAF日志中的 `REDIS_CONNECT_FAILED` 错误
- 确认防火墙允许本地6379端口通信

### 3. 误拦截问题

- 查看Nginx错误日志中的拦截事件和原因
- 将误拦截的IP添加到白名单
- 调整相关阈值（如 `bypass_window_limit`）
- 禁用特定检测规则（如 `block_empty_cookie = false`）

### 4. 共享内存占满

- 增大 `lua_shared_dict` 容量（建议从16m增至32m或64m）
- 缩短 `local_ban_cache_ttl` 减少缓存时间
- 查看日志中的 `SHM_CRITICAL` 告警

---

## 版本兼容性

| 组件 | 推荐版本 | 最低要求 |
|------|---------|---------|
| OpenResty | ≥ 1.21.4 | 1.15.8（需 `ngx.worker` API 支持） |
| Redis | ≥ 7.0 | 6.0（需 Lua 脚本原子执行能力） |
| Cloudflare | 任意套餐 | Free 及以上 |

> **说明**：推荐版本基于生产环境最佳实践。OpenResty 1.21.4+ 正则 JIT 完全生效，性能最优；Redis 7.0+ 提供更好的内存管理和脚本执行效率。

---

## 性能调优

### 关键参数

| 参数 | 默认值 | 建议值 |
|------|--------|--------|
| `redis_connect_timeout_ms` | 30 | 保持在50ms以下，快速失败 |
| `redis_eval_timeout_ms` | 100 | 给Redis足够的Lua计算时间 |
| `redis_keepalive_pool` | 自动计算 | `maxclients × 0.8 / worker_count`，最大200 |
| `redis_max_connections` | 1024 | 检查 `redis-cli CONFIG GET maxclients` |
| `malicious_params_min_len` | 8 | 增大可跳过更多短请求 |
| `malicious_params_regex_max_len` | 1024 | CPU受限可适当减小 |
| `global_req_flood_threshold` | 5000 | 每10秒，根据你的流量调整 |
| `bypass_window_limit` | 30 | 60s内BYPASS阈值（高于MISS的8，适配合法使用） |
| `miss_window_limit` | 8 | 60s内MISS阈值（正常首次访问） |

### Worker 数量与 Redis 连接池

连接池大小按每个Worker自动计算：

```lua
pool_per_worker = min(200, max(10, floor(max_redis_connections × 0.8 / worker_count)))
```

例如：8个Worker，Redis `maxclients=10000`：
`pool = min(200, 10000 × 0.8 / 8) = 200` 每个Worker = 总计1600个连接。

---

## 术语表

- **lua_shared_dict**：OpenResty提供的跨Worker共享内存字典，用于存储全局状态
- **cosocket**：OpenResty的非阻塞套接字API，用于高性能网络通信
- **熵值评分**：衡量字符串随机性的指标，高熵值通常表示恶意payload
- **分布式锁**：在多Worker/多服务器环境下保证操作原子性的机制
- **正则JIT**：LuaJIT对正则表达式的即时编译，可将匹配速度提升3-10倍
- **熔断机制**：当依赖服务（如Redis）故障时，快速失败并降级的保护机制
- **原始URI验证**：使用 `ngx.var.request_uri`（而非重写后的`ngx.var.uri`）做路径匹配，防止WordPress URL重写导致豁免失效

---

## 常见问题

### Q: 为什么已登录用户仍然会被检测？

A: 完全豁免会在管理员凭证泄露时形成攻击面。基线检查保留了关键防护（RCE、路径穿越、极端UA、查询长度），同时跳过了昂贵的操作（Redis评分、SQLi/XSS正则、熵值计算）。Cookie 需要 WordPress 签名格式（`user|expiry|token|hmac`）才能通过。

### Q: WAF 如何区分正常刷新和恶意绕过？

A: 正常浏览器刷新产生缓存 `MISS`（首次访问或缓存过期）。恶意绕过产生 `BYPASS`（主动缓存规避）。WAF对两者使用不同的阈值，并按IP跟踪频率。`bypass_window_limit`（默认30）高于 `miss_window_limit`（默认8）以适应合法使用场景。

### Q: Redis 宕机时会发生什么？

A: 熔断器激活并采用阶梯式退避（10s→20s→60s）。WAF通过本地共享内存继续提供基础防护：
- 检查本地封禁缓存
- 拦截高风险请求（quick_score ≥ 35）
- 长时间中断（>30s）时升级到更严格的阈值
- 后台定时器自动探测Redis恢复情况

### Q: 这个 WAF 可以不依赖 Cloudflare 运行吗？

A: 虽然针对Cloudflare优化，但可以。CF信任评分会降至最低，但所有其他防护层仍然有效。如果你不使用CDN，请设置 `bypass_block_immediately = false`，因为所有直接请求都会具有"绕过"特征。

### Q: 如何更新恶意参数规则？

A: 编辑 `cfg` 部分的 `malicious_rce`、`malicious_sqli` 和 `malicious_xss` 表，然后重载Nginx（`nginx -s reload`）。无需编译。

### Q: 如何查看 WAF 的运行状态？

A: 可以通过编程式API获取状态：

```lua
local status = waf.get_status()
ngx.say("当前模式: ", status.mode)
ngx.say("精确白名单数量: ", #status.whitelist_exact)
ngx.say("前缀白名单数量: ", #status.whitelist_prefix)
ngx.say("最后白名单刷新时间: ", status.last_whitelist_reload)
```

---

## 安全设计说明

### 正则安全

- 所有正则使用 `"joi"` 标志：JIT编译、匹配一次即返回、不区分大小写
- 输入截断至 `cfg.malicious_params_regex_max_len`（默认1024）以防止正则DoS
- 所有正则操作包裹在 `pcall` 中；失败时开放通过（不阻塞请求）
- 模式在适当位置自动添加 `\b` 单词边界

### 递归 URL 解码

- 最大20次迭代以防止无限循环
- 检测多重编码绕过尝试（`%252e → %2e → .`）
- 路径穿越检测使用完全解码；参数匹配使用部分解码

### 资源保护

- `set_keepalive` 失败时显式调用 `close()` 防止文件描述符泄漏
- `pcall + finally` 模式确保文件句柄和Redis连接始终被释放
- 日志阶段使用 `ngx.timer.at`（日志阶段不允许直接使用cosocket）
- 使用 `ZREMRANGEBYRANK` 替代 `unpack(zrange...)` 防止大有序集合时栈溢出

### 分布式锁安全

- 锁值包含PID和时间戳用于身份验证
- `safe_release_distributed_lock()` 仅在值匹配时删除（防止跨Worker竞态条件）
- 过期锁检测带2秒时钟漂移容差
- 生产环境建议配置NTP时间同步

### TOCTOU 竞态保护

- 共享内存计数器 get+check+set 合并到同一 `pcall`
- 熔断器重置使用原子性验证
- 分布式锁仅值匹配时释放

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交你的更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

如果你发现安全问题，请通过私下渠道报告，而非创建公开 Issue。

我的联系邮箱：mxianos32@gmail.com or mxianos32@qq.com

---

## 许可证

本项目基于 MIT License 开源。详见 [LICENSE](LICENSE) 文件。

Copyright (c) 2024-2026

---

## 免责声明

本 WAF 按"原样"提供，不提供任何形式的明示或暗示担保。虽然专为运行在 Cloudflare 后的生产 WordPress 站点设计，但你应在部署到生产环境之前在测试环境中彻底测试所有配置。作者不对因使用本软件造成的任何拦截、数据丢失或服务中断承担责任。
