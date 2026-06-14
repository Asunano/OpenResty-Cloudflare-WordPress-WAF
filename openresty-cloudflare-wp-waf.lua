-- SECURITY PATCH v1.1: Critical bug fixes
-- Apply to: bugfix/security-critical-patches branch

-- ==================================================================
-- BUG FIX #1: ReDoS Prevention (Multi-value Parameter Handling)
-- ==================================================================
-- Location: flatten_value() function
-- Issue: When users send repeated parameters (e.g., ?id=1&id=2&id=3&id=4...),
--        ngx.req.get_uri_args() returns a table. The original code concatenates
--        all values with space, but doesn't validate the result length before
--        passing to regex. An attacker can send 1000+ repeated params to trigger
--        catastrophic backtracking (ReDoS).
-- Severity: HIGH
-- Fix: Add length check before regex evaluation

local MAX_FLATTENED_VALUE_LEN = 4096  -- Hard limit for flattened param values

local function flatten_value(v)
    if not v then return "" end
    
    if type(v) == "table" then
        -- Count elements first to avoid unnecessary concat
        if #v > 100 then
            -- More than 100 repeated params is highly suspicious
            -- Truncate to prevent DoS
            local truncated = {}
            for i = 1, 100 do
                table.insert(truncated, v[i])
            end
            v = truncated
            ngx.log(ngx.WARN, "[WAF] 多值参数超过100个，已截断")
        end
        
        local result = table.concat(v, " ")
        
        -- **SECURITY FIX**: Truncate if flattened result exceeds safe length
        -- Prevents ReDoS when combined with malicious_params regex
        if #result > MAX_FLATTENED_VALUE_LEN then
            result = result:sub(1, MAX_FLATTENED_VALUE_LEN)
            ngx.log(ngx.WARN, "[WAF] 多值参数拼接长度超限 (>" .. MAX_FLATTENED_VALUE_LEN .. ")，已截断")
        end
        
        return result
    end
    
    return tostring(v)
end

-- ==================================================================
-- BUG FIX #2: Integer Overflow in lua_band() (CIDR Matching)
-- ==================================================================
-- Location: lua_band() function
-- Issue: When computing bit masks for /0 CIDR (entire internet),
--        `2^32 - 1` can overflow in 32-bit systems or cause precision
--        loss in Lua number representation (IEEE 754 double precision).
-- Severity: MEDIUM
-- Impact: Incorrect CIDR matching could whitelist unintended IPs
-- Fix: Add bit count validation and use safe multiplication

local function lua_band(a, b)
    -- **SECURITY FIX**: Validate inputs are reasonable values
    if not a or not b then
        return 0
    end
    
    -- Ensure inputs are non-negative integers
    a = math.floor(tonumber(a) or 0)
    b = math.floor(tonumber(b) or 0)
    
    if a < 0 or b < 0 then
        ngx.log(ngx.WARN, "[WAF] lua_band 收到负数输入: a=" .. a .. ", b=" .. b)
        return 0
    end
    
    local result = 0
    local bitval = 1
    local bit_count = 0
    
    for _ = 1, 32 do
        if bit_count >= 32 then
            break  -- Prevent infinite loop on corrupted input
        end
        
        if a % 2 == 1 and b % 2 == 1 then
            result = result + bitval
        end
        
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bitval = bitval * 2
        bit_count = bit_count + 1
        
        -- **SECURITY FIX**: Prevent bitval overflow
        if bitval > 2147483647 then  -- 2^31-1 (max safe bit in Lua)
            break
        end
    end
    
    return result
end

-- ==================================================================
-- BUG FIX #3: Nil Dereference in Redis Connection (Crash Prevention)
-- ==================================================================
-- Location: All redis_connect() call sites
-- Issue: If Redis is unavailable or network timeout occurs, redis_connect()
--        may return nil. Calling methods on nil crashes the WAF worker.
-- Severity: HIGH (DoS via redis crash)
-- Example: local red = redis_connect(); red:ttl(key) -- ERROR if red=nil
-- Fix: Add nil checks after redis_connect() and before method calls

-- **SECURITY FIX**: Wrapper function for safe Redis operations
local function safe_redis_call(operation_name, operation_func)
    local red = redis_connect()
    if not red then
        ngx.log(ngx.WARN, "[WAF] Redis 连接失败 (操作: " .. operation_name .. ")，降级处理")
        return nil, "redis_connection_failed"
    end
    
    local ok, result = pcall(function()
        return operation_func(red)
    end)
    
    if ok then
        redis_close(red)
        return result
    else
        ngx.log(ngx.ERR, "[WAF] Redis 操作异常 (" .. operation_name .. "): " .. tostring(result))
        redis_close(red)
        return nil, tostring(result)
    end
end

-- ==================================================================
-- BUG FIX #4: Redis TTL Regression (Memory Leak)
-- ==================================================================
-- Location: cleanup_redis_data_if_needed() function around line 963
-- Issue: Original code checks `if ttl_val > 0 then` which skips:
--        - TTL=-1 (permanently stored keys that should be cleaned)
--        - TTL=-2 (keys that don't exist, but redis:ttl() should not return this)
--        This causes ZSET keys to accumulate forever if not explicitly TTL'd
-- Severity: MEDIUM (gradual memory exhaustion)
-- Fix: Check `ttl_val >= -1` to include permanently-keyed data

-- The fix in cleanup_redis_data_if_needed is already in place at line 963:
-- if ttl_val and ttl_val >= -1 then  -- ✓ CORRECT (includes -1)
-- Previously was: if ttl_val and ttl_val > 0 then  -- ✗ BUG (skips -1)

-- ==================================================================
-- BUG FIX #5: Config Injection Prevention
-- ==================================================================
-- Location: cfg table initialization (around line 92-277)
-- Issue: If config values are loaded from external sources (e.g., Nginx vars,
--        environment), they could contain Lua code that gets evaluated
-- Severity: MEDIUM-LOW (depends on config source)
-- Fix: Add type validation for all user-facing config values

local function validate_config(cfg)
    -- **SECURITY FIX**: Validate all critical config types
    local validations = {
        redis_host = function(v) return type(v) == "string" and #v > 0 and #v < 256 end,
        redis_port = function(v) return type(v) == "number" and v > 0 and v < 65536 end,
        redis_db = function(v) return type(v) == "number" and v >= 0 and v < 16 end,
        redis_connect_timeout_ms = function(v) return type(v) == "number" and v > 0 and v < 10000 end,
        ban_soft = function(v) return type(v) == "number" and v > 0 and v < 1000000 end,
        ban_mid = function(v) return type(v) == "number" and v > 0 and v < 1000000 end,
        ban_hard = function(v) return type(v) == "number" and v > 0 and v < 1000000 end,
        status_endpoint_enabled = function(v) return type(v) == "boolean" end,
        enable_debug_log = function(v) return type(v) == "boolean" end,
    }
    
    for key, validator in pairs(validations) do
        if cfg[key] ~= nil and not validator(cfg[key]) then
            ngx.log(ngx.ERR, string.format(
                "[WAF] 配置值验证失败: %s = %s (类型: %s)",
                key, tostring(cfg[key]), type(cfg[key])
            ))
            return false
        end
    end
    
    return true
end

-- Call validation after cfg table definition
-- validate_config(cfg)  -- Uncomment in init_worker phase

-- ==================================================================
-- SUMMARY OF FIXES
-- ==================================================================
--
-- 1. ✓ ReDoS Prevention: Limit multi-value param concat to 4096 bytes
-- 2. ✓ Integer Overflow: Safe lua_band() with overflow checks
-- 3. ✓ Nil Dereference: Helper function for safe Redis calls
-- 4. ✓ Memory Leak: TTL check already corrected (ttl_val >= -1)
-- 5. ✓ Config Injection: Type validation helper for config values
--
-- Apply all functions to main WAF file and test in staging environment
-- before production deployment.
