/// Adaptive Rate Limiter
/// Multi-dimensional: global, per-IP, per-session, per-endpoint.
/// Algorithms: sliding window (Redis) + token bucket + EWMA burst detection.
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub count: u64,
    pub limit: u64,
    pub remaining: u64,
    pub retry_after_ms: u64,
    pub is_burst: bool,
    pub score_delta: u32,
}

pub struct RateLimiter {
    redis: MultiplexedConnection,
    ewma_alpha: f64,
}

impl RateLimiter {
    pub fn new(redis: MultiplexedConnection) -> Self {
        Self { redis, ewma_alpha: 0.1 }
    }

    /// Sliding window rate limit check.
    /// Uses a sorted set: key = "rl:{scope}:{id}", member = "{timestamp}-{rand}", score = timestamp.
    pub async fn check(
        &mut self,
        scope: &str,
        id: &str,
        limit: u64,
        window_ms: u64,
    ) -> anyhow::Result<RateLimitResult> {
        let now_ms = now_ms();
        let window_start = now_ms.saturating_sub(window_ms);
        let key = format!("rl:{}:{}", scope, id);
        let member = format!("{}-{}", now_ms, fastrand::u64(..));

        let (count,): (u64,) = redis::pipe()
            .zrembyscore(&key, 0i64, window_start as i64)
            .ignore()
            .zadd(&key, &member, now_ms as i64)
            .ignore()
            .zcard(&key)
            .pexpire(&key, window_ms as usize)
            .ignore()
            .query_async(&mut self.redis)
            .await?;

        let allowed = count <= limit;
        let remaining = limit.saturating_sub(count);
        let retry_after_ms = if allowed { 0 } else { window_ms };

        Ok(RateLimitResult {
            allowed,
            count,
            limit,
            remaining,
            retry_after_ms,
            is_burst: false,
            score_delta: if allowed { 0 } else { 40 },
        })
    }

    /// Token bucket for burst control.
    pub async fn token_bucket(
        &mut self,
        key: &str,
        capacity: u64,
        refill_rate_per_sec: f64,
    ) -> anyhow::Result<RateLimitResult> {
        let now = now_ms() as f64 / 1000.0;
        let bucket_key = format!("tb:{}", key);

        // Lua script for atomic token bucket
        let lua = r#"
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])

            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or capacity
            local last_refill = tonumber(bucket[2]) or now

            local elapsed = now - last_refill
            tokens = math.min(capacity, tokens + elapsed * refill_rate)

            if tokens >= 1 then
                tokens = tokens - 1
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('PEXPIRE', key, 60000)
                return {1, math.floor(tokens)}
            else
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('PEXPIRE', key, 60000)
                return {0, 0}
            end
        "#;

        let (allowed, remaining): (u8, u64) = redis::Script::new(lua)
            .key(&bucket_key)
            .arg(capacity)
            .arg(refill_rate_per_sec)
            .arg(now)
            .invoke_async(&mut self.redis)
            .await?;

        Ok(RateLimitResult {
            allowed: allowed == 1,
            count: capacity - remaining,
            limit: capacity,
            remaining,
            retry_after_ms: if allowed == 1 { 0 } else { 1000 },
            is_burst: false,
            score_delta: if allowed == 1 { 0 } else { 35 },
        })
    }

    /// EWMA-based burst detection.
    /// Compares current rate against exponentially-weighted moving average.
    /// Returns true if current rate exceeds baseline by spike_factor.
    pub async fn detect_burst(
        &mut self,
        scope: &str,
        current_rps: f64,
        spike_factor: f64,
    ) -> anyhow::Result<bool> {
        let key = format!("ewma:{}", scope);

        let prev_ewma: Option<f64> = self.redis.get(&key).await.unwrap_or(None);
        let ewma = match prev_ewma {
            Some(prev) => self.ewma_alpha * current_rps + (1.0 - self.ewma_alpha) * prev,
            None       => current_rps,
        };

        let _: () = self.redis.set_ex(&key, ewma, 300).await?;

        Ok(current_rps > ewma * spike_factor)
    }

    /// All-in-one check: global + per-IP + per-session + per-endpoint.
    /// session_id is Option — pass None when no session cookie is present.
    /// Passing Some("") or a shared empty string would collapse all anonymous
    /// traffic into one bucket, causing false rate-limit triggers.
    pub async fn full_check(
        &mut self,
        ip: &str,
        session_id: Option<&str>,
        endpoint: &str,
        global_rps: u64,
        per_ip_rps: u64,
        per_session_rps: u64,
        endpoint_limit: Option<u64>,
    ) -> anyhow::Result<RateLimitDecision> {
        let mut decision = RateLimitDecision::default();

        // Global rate limit (1 second window)
        let global = self.check("global", "all", global_rps, 1000).await?;
        if !global.allowed {
            decision.blocked = true;
            decision.reason = "global_rate_limit".into();
            decision.score_delta += 20;
        }

        // Per-IP (60 second window)
        let per_ip = self.check("ip", ip, per_ip_rps * 60, 60_000).await?;
        if !per_ip.allowed {
            decision.blocked = true;
            decision.reason = "per_ip_rate_limit".into();
            decision.score_delta += 40;
        }

        // Per-session (10 second window) — only when a session cookie is present
        if let Some(sid) = session_id {
            let per_sess = self.check("session", sid, per_session_rps * 10, 10_000).await?;
            if !per_sess.allowed {
                decision.blocked = true;
                decision.reason = "per_session_rate_limit".into();
                decision.score_delta += 35;
            }
        }

        // Per-endpoint
        if let Some(ep_limit) = endpoint_limit {
            let ep = self.check("endpoint", endpoint, ep_limit, 60_000).await?;
            if !ep.allowed {
                decision.blocked = true;
                decision.reason = format!("endpoint_limit:{}", endpoint);
                decision.score_delta += 40;
            }
        }

        Ok(decision)
    }
}

#[derive(Debug, Default)]
pub struct RateLimitDecision {
    pub blocked: bool,
    pub reason: String,
    /// Accumulated score contribution from rate-limit violations.
    /// Currently not consumed by the middleware — the scorer applies points
    /// via the `rate_limit_violated` bool signal instead. Kept for future use
    /// if the middleware is extended to apply fine-grained score deltas directly.
    #[allow(dead_code)]
    pub score_delta: u32,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
