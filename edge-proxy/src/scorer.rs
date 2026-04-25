use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Every signal that contributes to the final risk score.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignalSet {
    // Network / IP signals
    pub is_datacenter_asn:     bool,
    pub is_tor_exit:           bool,
    pub is_vpn_proxy:          bool,
    pub is_cgnat:              bool,
    pub is_bogon:              bool,
    pub ip_reputation_score:   f32,   // 0..1 from threat intel feeds
    pub geo_velocity_violation: bool,

    // TLS signals
    pub ja3_suspicious:        bool,
    pub ja4_suspicious:        bool,
    pub tls_cipher_mismatch:   bool,
    pub tls_ticket_reuse:      bool,
    pub tls_handshake_anomaly: bool,

    // HTTP signals
    pub h2_settings_mismatch:  bool,
    pub h2_pseudo_header_order_wrong: bool,
    pub user_agent_absent:     bool,
    pub user_agent_bot:        bool,
    pub accept_language_absent: bool,
    pub header_order_anomaly:  bool,

    // Request pattern signals
    pub rate_limit_violated:   bool,
    pub burst_detected:        bool,
    pub zero_timing_jitter:    bool,
    pub honeypot_accessed:     bool,
    pub canary_triggered:      bool,
    pub request_flood:         bool,
    pub slow_http_attack:      bool,

    // Request content signals
    pub json_entropy_high:     bool,
    pub param_pollution:       bool,
    pub chunked_encoding_conflict: bool,
    pub invalid_crlf:          bool,
    pub path_traversal_attempt: bool,
    pub url_encoding_layers:   u8,   // >2 is suspicious

    // Browser / client signals (from JS telemetry)
    pub no_mouse_activity:     bool,
    pub linear_mouse_movement: bool,
    pub zero_scroll_inertia:   bool,
    pub no_keyboard_jitter:    bool,
    pub no_focus_events:       bool,
    pub navigator_webdriver:   bool,
    pub plugin_count_zero:     bool,
    pub screen_size_zero:      bool,
    pub no_languages:          bool,

    // Fingerprint signals
    pub fp_in_known_bot_cluster: bool,
    pub canvas_fp_anomaly:     bool,
    pub webgl_fp_anomaly:      bool,
    pub automation_framework_detected: bool,  // puppeteer/playwright/selenium

    // ML / behavior signals (from behavior engine)
    pub ml_anomaly_score:      f32,   // 0..1 from isolation forest
    pub sequence_bot_probability: f32, // 0..1 from LSTM
    pub cluster_community_id:  Option<String>, // if in known botnet cluster
    pub transformer_coordination_score: f32,

    // Session signals
    pub session_age_ms:        u64,
    pub navigation_entropy:    f32,
    pub click_variance:        f32,
    pub dwell_time_ms:         u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResult {
    pub total: u32,
    pub breakdown: HashMap<String, u32>,
    pub action: Action,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Allow,
    InvisibleChallenge,
    JsChallenge,
    /// difficulty: leading zero bits required (4–20).
    /// wasm: if true, serve the WASM compute challenge in addition to PoW.
    ProofOfWork { difficulty: u8, wasm: bool },
    Captcha,
    Block,
}

pub struct Scorer {
    block_threshold:       u32,
    captcha_threshold:     u32,
    pow_threshold:         u32,
    js_challenge_threshold: u32,
}

impl Scorer {
    pub fn new(block: u32, captcha: u32, pow: u32, js: u32) -> Self {
        Self {
            block_threshold: block,
            captcha_threshold: captcha,
            pow_threshold: pow,
            js_challenge_threshold: js,
        }
    }

    pub fn score(&self, s: &SignalSet) -> ScoreResult {
        let mut total: u32 = 0;
        let mut breakdown = HashMap::new();
        let mut reasons = Vec::new();

        macro_rules! add {
            ($cond:expr, $name:expr, $pts:expr) => {
                if $cond {
                    total += $pts;
                    breakdown.insert($name.to_string(), $pts);
                    reasons.push(format!("{} (+{})", $name, $pts));
                }
            };
        }

        // ── Instant block signals ─────────────────────────────────────
        add!(s.is_bogon,                "bogon_ip",                 100);
        add!(s.invalid_crlf,            "crlf_injection",           40);
        add!(s.path_traversal_attempt,  "path_traversal",           50);
        add!(s.canary_triggered,        "canary_triggered",         60);

        // ── High-weight signals ───────────────────────────────────────
        add!(s.navigator_webdriver,          "navigator_webdriver",       60);
        add!(s.honeypot_accessed,            "honeypot_accessed",         50);
        add!(s.automation_framework_detected,"automation_framework",      55);
        add!(s.fp_in_known_bot_cluster,      "botnet_cluster",            45);
        add!(s.rate_limit_violated,          "rate_limit",                40);
        add!(s.burst_detected,               "burst_detected",            35);
        add!(s.is_tor_exit,                  "tor_exit_node",             35);
        add!(s.request_flood,                "request_flood",             45);

        // ── Medium signals ────────────────────────────────────────────
        add!(s.is_datacenter_asn,        "datacenter_asn",           20);
        add!(s.no_mouse_activity,        "no_mouse_activity",        30);
        add!(s.linear_mouse_movement,    "linear_mouse",             25);
        add!(s.zero_timing_jitter,       "zero_timing_jitter",       20);
        add!(s.slow_http_attack,         "slow_http_attack",         40);
        add!(s.ja4_suspicious,           "ja4_mismatch",             25);
        add!(s.ja3_suspicious,           "ja3_suspicious",           20);
        add!(s.h2_pseudo_header_order_wrong, "h2_pseudo_header",     18);
        add!(s.h2_settings_mismatch,     "h2_settings",              15);
        add!(s.canvas_fp_anomaly,        "canvas_fp_anomaly",        20);
        add!(s.webgl_fp_anomaly,         "webgl_fp_anomaly",         20);
        add!(s.param_pollution,          "param_pollution",          15);
        add!(s.chunked_encoding_conflict,"chunked_conflict",         25);
        add!(s.json_entropy_high,        "json_entropy",             15);
        add!(s.geo_velocity_violation,   "geo_velocity",             40);
        add!(s.zero_scroll_inertia,      "zero_scroll_inertia",      20);
        add!(s.no_keyboard_jitter,       "no_keyboard_jitter",       15);
        add!(s.plugin_count_zero,        "no_plugins",               15);
        add!(s.screen_size_zero,         "zero_screen_size",         25);
        add!(s.no_languages,             "no_languages",             20);
        add!(s.tls_cipher_mismatch,      "tls_cipher_mismatch",      18);
        add!(s.user_agent_bot,           "bot_user_agent",           30);
        add!(s.user_agent_absent,        "no_user_agent",            20);
        add!(s.accept_language_absent,   "no_accept_language",       10);

        // ── Low-weight signals ────────────────────────────────────────
        add!(s.is_vpn_proxy,             "vpn_proxy",                10);
        add!(s.tls_ticket_reuse,         "tls_ticket_reuse",         10);
        add!(s.tls_handshake_anomaly,    "tls_handshake_anomaly",    12);
        add!(s.header_order_anomaly,     "header_order",             8);
        add!(s.no_focus_events,          "no_focus_events",          10);

        // ── URL encoding layers ───────────────────────────────────────
        if s.url_encoding_layers > 2 {
            let pts = (s.url_encoding_layers as u32 - 2) * 10;
            total += pts;
            breakdown.insert("url_encoding_layers".into(), pts);
            reasons.push(format!("url_encoding_layers={} (+{})", s.url_encoding_layers, pts));
        }

        // ── Continuous ML scores ──────────────────────────────────────
        if s.ml_anomaly_score > 0.5 {
            let pts = ((s.ml_anomaly_score - 0.5) * 60.0) as u32;
            total += pts;
            breakdown.insert("ml_anomaly".into(), pts);
            reasons.push(format!("ml_anomaly_score={:.3} (+{})", s.ml_anomaly_score, pts));
        }

        if s.sequence_bot_probability > 0.6 {
            let pts = ((s.sequence_bot_probability - 0.6) * 50.0) as u32;
            total += pts;
            breakdown.insert("sequence_bot".into(), pts);
            reasons.push(format!("sequence_bot_prob={:.3} (+{})", s.sequence_bot_probability, pts));
        }

        if s.transformer_coordination_score > 0.7 {
            let pts = ((s.transformer_coordination_score - 0.7) * 40.0) as u32;
            total += pts;
            breakdown.insert("coordination".into(), pts);
        }

        // ── IP reputation ─────────────────────────────────────────────
        if s.ip_reputation_score > 0.3 {
            let pts = (s.ip_reputation_score * 30.0) as u32;
            total += pts;
            breakdown.insert("ip_reputation".into(), pts);
        }

        // ── Determine action ─────────────────────────────────────────
        let action = if total >= self.block_threshold {
            Action::Block
        } else if total >= self.captcha_threshold {
            Action::Captcha
        } else if total >= self.pow_threshold {
            // Scale PoW difficulty 4..20 bits based on score within the PoW band.
            // Guard against misconfigured equal thresholds (band = 0) which would
            // cause a float divide-by-zero and an overflow cast to u8.
            let band = (self.captcha_threshold - self.pow_threshold) as f32;
            let band = if band <= 0.0 { 1.0 } else { band };
            let pos  = (total - self.pow_threshold) as f32;
            let difficulty = 4u8 + (pos / band * 16.0).min(16.0) as u8;
            // At score >= 30% of the PoW band, also require the WASM challenge
            let wasm = pos / band >= 0.3;
            Action::ProofOfWork { difficulty, wasm }
        } else if total >= self.js_challenge_threshold {
            Action::JsChallenge
        } else if total >= 20 {
            Action::InvisibleChallenge
        } else {
            Action::Allow
        };

        ScoreResult { total, breakdown, action, reasons }
    }
}
