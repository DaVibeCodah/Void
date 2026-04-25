/// Core Shield Middleware Pipeline
/// Orchestrates all detection layers for each incoming request.
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{info, warn, debug};

use crate::config::Config;
use crate::ip_intel::IpIntelEngine;
use crate::normalizer::Normalizer;
use crate::proxy::ReverseProxy;
use crate::ratelimit::RateLimiter;
use crate::scorer::{Action, ScoreResult, Scorer, SignalSet};
use crate::session::{BrowserFingerprint, BehaviorTelemetry, Session, SessionStore};
use crate::tls_fp::TlsFingerprint;
use crate::http2_fp::{Http2Fingerprint, TimingAnalyzer};

pub struct ShieldMiddleware {
    cfg:       Arc<Config>,
    scorer:    Scorer,
    normalizer: Normalizer,
    ip_intel:  Arc<tokio::sync::Mutex<IpIntelEngine>>,
    sessions:  Arc<tokio::sync::Mutex<SessionStore>>,
    ratelimit: Arc<tokio::sync::Mutex<RateLimiter>>,
    honeypot_paths: Vec<String>,
    /// Shared HTTP client for ML engine calls — holds a connection pool and DNS
    /// cache. Building one per request would defeat keep-alive, re-resolve DNS on
    /// every call, and consume the 30ms ML budget on connection setup under load.
    http_client: reqwest::Client,
}

impl ShieldMiddleware {
    pub async fn new(cfg: Arc<Config>) -> anyhow::Result<Self> {
        let redis_client = redis::Client::open(cfg.redis_url.as_str())?;
        let redis_conn = redis_client.get_multiplexed_tokio_connection().await?;
        let redis_conn2 = redis_client.get_multiplexed_tokio_connection().await?;

        let ip_intel = IpIntelEngine::new(&cfg.asn_db, &cfg.geoip_db).await?;
        let session_store = SessionStore::new(redis_conn.clone());
        let rate_limiter  = RateLimiter::new(redis_conn2);

        let scorer = Scorer::new(
            cfg.block_score_threshold,
            cfg.captcha_score_threshold,
            cfg.pow_score_threshold,
            cfg.js_challenge_score_threshold,
        );

        Ok(Self {
            honeypot_paths: cfg.honeypot_paths.clone(),
            cfg,
            scorer,
            normalizer: Normalizer::default(),
            ip_intel:  Arc::new(tokio::sync::Mutex::new(ip_intel)),
            sessions:  Arc::new(tokio::sync::Mutex::new(session_store)),
            ratelimit: Arc::new(tokio::sync::Mutex::new(rate_limiter)),
            http_client: reqwest::Client::builder()
                .pool_max_idle_per_host(4)
                .timeout(std::time::Duration::from_millis(30))
                .build()?,
        })
    }

    pub async fn handle(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        proxy: Arc<ReverseProxy>,
    ) -> anyhow::Result<()> {
        let ip = peer_addr.ip();

        // ── L1: IP Intelligence ───────────────────────────────────────
        let intel = {
            let engine = self.ip_intel.lock().await;
            engine.classify(ip)
        };

        let mut signals = SignalSet {
            is_datacenter_asn:     intel.is_datacenter,
            is_tor_exit:           intel.is_tor,
            is_vpn_proxy:          intel.is_vpn || intel.is_proxy,
            is_bogon:              intel.is_bogon,
            is_cgnat:              intel.is_cgnat,
            ip_reputation_score:   intel.reputation_score,
            ..Default::default()
        };

        // Immediately drop bogon IPs
        if signals.is_bogon {
            warn!("Dropping bogon IP: {}", ip);
            return Ok(());
        }

        // ── Parse HTTP request (simplified - real impl uses hyper) ────
        // In production: full HTTP/1.1 + HTTP/2 + HTTP/3 parsing
        let raw_path   = "/";  // extracted from request
        let user_agent = "";   // extracted from headers
        // None = no session cookie present. Passing an empty string would collapse
        // all unauthenticated traffic into a single shared rate-limit bucket.
        let session_id: Option<&str> = None; // extracted from __void_pass cookie

        // ── L2: Request Normalization ─────────────────────────────────
        let normalized = match self.normalizer.normalize(raw_path) {
            Ok(n) => n,
            Err(e) => {
                warn!("Normalization error for {}: {}", ip, e);
                signals.url_encoding_layers = 10; // max penalty
                return proxy.serve_block_response(stream, "invalid_request").await;
            }
        };

        signals.url_encoding_layers = normalized.encoding_layers;
        if normalized.had_crlf          { signals.invalid_crlf = true; }
        if normalized.had_traversal     { signals.path_traversal_attempt = true; }

        // ── L3: Honeypot check ────────────────────────────────────────
        if self.honeypot_paths.contains(&normalized.path) {
            signals.honeypot_accessed = true;
            // Serve fake content and record session, but also flag the reason so
            // serve_block_response increments honeypot_hits_today correctly.
            warn!("Honeypot triggered: {} -> {}", ip, normalized.path);
        }

        // ── L4: Rate limiting ─────────────────────────────────────────
        let ep_limit = self.cfg.endpoint_limits
            .get(&normalized.path)
            .map(|l| l.rps);

        let rl_decision = {
            let mut rl = self.ratelimit.lock().await;
            rl.full_check(
                &ip.to_string(),
                session_id,
                &normalized.path,
                self.cfg.global_rps_limit,
                self.cfg.per_ip_rps_limit,
                self.cfg.per_session_rps_limit,
                ep_limit,
            ).await?
        };

        if rl_decision.blocked {
            signals.rate_limit_violated = true;
        }

        // ── L5: Header analysis ───────────────────────────────────────
        // (headers extracted from raw request in production)
        signals.user_agent_absent = user_agent.is_empty();
        if user_agent.to_lowercase().contains("bot")
        || user_agent.to_lowercase().contains("spider")
        || user_agent.to_lowercase().contains("crawler")
        || user_agent.to_lowercase().contains("python-requests")
        || user_agent.to_lowercase().contains("curl/")
        || user_agent.to_lowercase().contains("scrapy") {
            signals.user_agent_bot = true;
        }

        // ── L6: Session lookup & behavior ────────────────────────────
        if let Some(sid) = session_id {
            // Acquire lock, clone the data we need, then immediately drop the lock.
            let session_data = {
                let mut store = self.sessions.lock().await;
                store.get(sid).await
            }; // lock dropped here

            if let Some(session) = session_data {
                signals.no_mouse_activity = !session.mouse_events_received;
                signals.no_focus_events   = !session.focus_events_received;

                // Timing jitter analysis
                if session.timing_intervals.len() >= 5 {
                    let intervals = &session.timing_intervals;
                    let mean: f64 = intervals.iter().sum::<f64>() / intervals.len() as f64;
                    let variance: f64 = intervals.iter()
                        .map(|x| (x - mean).powi(2))
                        .sum::<f64>() / intervals.len() as f64;
                    if variance.sqrt() < 2.0 {
                        signals.zero_timing_jitter = true;
                    }
                }

                // Geo velocity: use real last_seen timestamp delta, not a hardcoded 60s.
                // session.last_seen is a Unix timestamp in milliseconds.
                if let (Some(lat1), Some(lon1)) = (session.last_latitude, session.last_longitude) {
                    if let (Some(lat2), Some(lon2)) = (intel.latitude, intel.longitude) {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_seconds = if now_ms > session.last_seen && session.last_seen > 0 {
                            (now_ms - session.last_seen) as f64 / 1000.0
                        } else {
                            // No prior timestamp recorded yet — skip the check
                            f64::MAX
                        };
                        if elapsed_seconds < f64::MAX
                            && IpIntelEngine::is_geo_velocity_impossible(lat1, lon1, lat2, lon2, elapsed_seconds)
                        {
                            signals.geo_velocity_violation = true;
                            warn!("Geo velocity violation for session {}", sid);
                        }
                    }
                }

                // Fingerprint cluster check — separate lock acquisition, no deadlock risk
                if let Some(ref fp_hash) = session.fingerprint_hash {
                    let cluster_size = {
                        let mut store = self.sessions.lock().await;
                        store.fingerprint_cluster_size(fp_hash).await
                    };
                    if cluster_size > 5 {
                        signals.fp_in_known_bot_cluster = true;
                        warn!("Fingerprint {} seen from {} IPs — bot cluster", fp_hash, cluster_size);
                    }
                }
            }
        }

        // ── L7: ML Behavior Engine call ───────────────────────────────
        if let Ok(ml_result) = self.call_behavior_engine(&signals, &ip.to_string()).await {
            signals.ml_anomaly_score             = ml_result.anomaly_score;
            signals.sequence_bot_probability     = ml_result.sequence_bot_probability;
            signals.transformer_coordination_score = ml_result.coordination_score;
            if ml_result.in_botnet_cluster {
                signals.fp_in_known_bot_cluster = true;
            }
        }

        // ── L8: Score aggregation ─────────────────────────────────────
        let result = self.scorer.score(&signals);

        debug!("Request from {} scored {} -> {:?}", ip, result.total, result.action);

        if result.total > 20 {
            info!("Elevated score {} for {}: {:?}", result.total, ip, result.reasons);
        }

        // ── L9: Action dispatch ───────────────────────────────────────
        match &result.action {
            Action::Allow => {
                proxy.forward(stream, &normalized.path).await
            }
            Action::InvisibleChallenge => {
                proxy.serve_with_telemetry_injection(stream, &normalized.path).await
            }
            Action::JsChallenge => {
                proxy.serve_js_challenge(stream, &result).await
            }
            Action::ProofOfWork { difficulty, wasm } => {
                proxy.serve_pow_challenge(stream, *difficulty, *wasm, &result).await
            }
            Action::Captcha => {
                proxy.serve_captcha_challenge(stream, &result).await
            }
            Action::Block => {
                // Preserve honeypot reason so the stat counter fires correctly.
                let reason = if signals.honeypot_accessed { "honeypot" } else { "blocked" };
                proxy.serve_block_response(stream, reason).await
            }
        }
    }

    async fn call_behavior_engine(
        &self,
        signals: &SignalSet,
        ip: &str,
    ) -> anyhow::Result<BehaviorEngineResponse> {
        // Reuse the shared client — it holds a connection pool and DNS cache.
        // The timeout is set once at construction in ShieldMiddleware::new.
        let response = self.http_client
            .post(format!("{}/score", self.cfg.behavior_engine_url))
            .json(&serde_json::json!({
                "ip": ip,
                "signals": signals,
            }))
            .send()
            .await?
            .json::<BehaviorEngineResponse>()
            .await?;
        Ok(response)
    }
}

#[derive(serde::Deserialize, Default)]
struct BehaviorEngineResponse {
    anomaly_score: f32,
    sequence_bot_probability: f32,
    coordination_score: f32,
    in_botnet_cluster: bool,
}
