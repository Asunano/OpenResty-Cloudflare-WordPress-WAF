# OpenResty-Cloudflare-WordPress-WAF
基于 OpenResty+Cloudflare+Redis 打造的 WordPress 专属高性能 WAF，提供四层渐进式防护；支持 Redis 风险评分、自动防护模式切换、恶意 UA / 参数 / 路径穿越检测，具备频率限制、梯度封禁、IP 白名单（CIDR）、Redis 熔断降级能力，深度适配 WordPress 生态，低误判、高兼容，兼顾安全与性能。
